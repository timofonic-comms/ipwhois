import sys
import re
import copy
from datetime import datetime
import logging
from .utils import unique_everseen
from . import (BlacklistError, WhoisLookupError, NetError)

if sys.version_info >= (3, 3):  # pragma: no cover
    from ipaddress import (ip_address,
                           ip_network,
                           summarize_address_range,
                           collapse_addresses)
else:  # pragma: no cover
    from ipaddr import (IPAddress as ip_address,
                        IPNetwork as ip_network,
                        summarize_address_range,
                        collapse_address_list as collapse_addresses)

log = logging.getLogger(__name__)

# Legacy base whois output dictionary.
BASE_NET = {
    'cidr': None,
    'name': None,
    'handle': None,
    'range': None,
    'description': None,
    'country': None,
    'state': None,
    'city': None,
    'address': None,
    'postal_code': None,
    'emails': None,
    'created': None,
    'updated': None
}

RIR_WHOIS = {
    'jpnic': {
        'server': 'whois.nic.ad.jp',
        'fields': {
            'name': r'b\. \[[^\]]+\] +(?P<val>.+?)\n',
            'description': r'f\. \[[^\]]+\] +(?P<val>.+?)\n',
            'updated': r'\[[^\]]+\] +(?P<val>[0-9/]{10}) [0-9:]{8}\(JST\)\n',
            'created': r'\[[^\]]+\] +(?P<val>[0-9/]{10})\n',
            #'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'emails': (
                r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)('
                '[^\S\n]+.*?)*?\n'
            ),
        },
        'dt_format': '%Y/%m/%d'
    },
}

class JPWhois:
    """
    The class for parsing via whois

    Args:
        net: A ipwhois.net.Net object.

    Raises:
        NetError: The parameter provided is not an instance of
            ipwhois.net.Net
        IPDefinedError: The address provided is defined (does not need to be
            resolved).
    """

    def __init__(self, net):

        from .net import Net

        # ipwhois.net.Net validation
        if isinstance(net, Net):

            self._net = net

        else:

            raise NetError('The provided net parameter is not an instance of '
                           'ipwhois.net.Net')

    def _parse_fields(self, response, fields_dict, net_start=None,
                      net_end=None, dt_format=None, field_list=None):
        """
        The function for parsing whois fields from a data input.

        Args:
            response: The response from the whois/rwhois server.
            fields_dict: The dictionary of fields -> regex search values.
            net_start: The starting point of the network (if parsing multiple
                networks).
            net_end: The ending point of the network (if parsing multiple
                networks).
            dt_format: The format of datetime fields if known.
            field_list: If provided, a list of fields to parse:
                ['name', 'handle', 'description', 'country', 'state', 'city',
                'address', 'postal_code', 'emails', 'created', 'updated']

        Returns:
            Dictionary: A dictionary of fields provided in fields_dict.
        """

        ret = {}

        if not field_list:

            field_list = ['name', 'handle', 'description', 'country', 'state',
                          'city', 'address', 'postal_code', 'emails',
                          'created', 'updated']

        generate = ((field, pattern) for (field, pattern) in
                    fields_dict.items() if field in field_list)

        for field, pattern in generate:
            pattern = re.compile(
                str(pattern),
                re.DOTALL
            )

            if net_start is not None:

                match = pattern.finditer(response, net_end, net_start)

            elif net_end is not None:

                match = pattern.finditer(response, net_end)

            else:

                match = pattern.finditer(response)

            values = []
            sub_section_end = None
            for m in match:

                if sub_section_end:

                    if field not in (
                        'emails'
                    ) and (sub_section_end != (m.start() - 1)):

                        break

                try:

                    values.append(m.group('val').strip())

                except IndexError:

                    pass

                sub_section_end = m.end()

            if len(values) > 0:

                value = None
                try:

                    if field == 'country':

                        value = values[0].upper()

                    elif field in ['created', 'updated'] and dt_format:

                        value = datetime.strptime(
                            values[0],
                            str(dt_format)).isoformat('T')

                    elif field in ['emails']:

                        value = list(unique_everseen(values))

                    else:

                        values = unique_everseen(values)
                        value = '\n'.join(values).strip()

                except ValueError as e:

                    log.debug('Whois field parsing failed for {0}: {1}'.format(
                        field, e))
                    pass

                ret[field] = value

        return ret

    def _get_nets_jpnic(self, response):
        nets = []

        # Iterate through all of the networks found, storing the CIDR value
        # and the start and end positions.
        for match in re.finditer(
            r'^a. \[[^]]+\] +(.+)$',
            response,
            re.MULTILINE
        ):

            try:

                net = copy.deepcopy(BASE_NET)
                net['range'] = match.group(1)
                cidr = ip_network(match.group(1).strip()).__str__()

                net['cidr'] = cidr
                net['start'] = match.start()
                net['end'] = match.end()
                net['country'] = 'JP'
                nets.append(net)

            except (ValueError, TypeError):

                pass

        return nets

    def lookup(self, inc_raw=False, retry_count=3, response=None,
               asn_data=None,
               field_list=None, is_offline=False):
        """
        The function for retrieving and parsing whois information for an IP
        address via port 43/tcp (WHOIS).

        Args:
            inc_raw: Boolean for whether to include the raw results in the
                returned dictionary.
            retry_count: The number of times to retry in case socket errors,
                timeouts, connection resets, etc. are encountered.
            response: Optional response object, this bypasses the Whois lookup.
            get_referral: Boolean for whether to retrieve referral whois
                information, if available.
            extra_blacklist: A list of blacklisted whois servers in addition to
                the global BLACKLIST.
            ignore_referral_errors: Boolean for whether to ignore and continue
                when an exception is encountered on referral whois lookups.
            asn_data: Optional ASN result object, this bypasses the ASN lookup.
            field_list: If provided, a list of fields to parse:
                ['name', 'handle', 'description', 'country', 'state', 'city',
                'address', 'postal_code', 'emails', 'created', 'updated']
            is_offline: Boolean for whether to perform lookups offline. If
                True, response and asn_data must be provided. Primarily used
                for testing.

        Returns:
            Dictionary:

            :query: The IP address (String)
            :asn: The Autonomous System Number (String)
            :asn_date: The ASN Allocation date (String)
            :asn_registry: The assigned ASN registry (String)
            :asn_cidr: The assigned ASN CIDR (String)
            :asn_country_code: The assigned ASN country code (String)
            :nets: Dictionaries containing network information which consists
                of the fields listed in the NIC_WHOIS dictionary. (List)
            :raw: Raw whois results if the inc_raw parameter is True. (String)
            :referral: Dictionary of referral whois information if get_referral
                is True and the server isn't blacklisted. Consists of fields
                listed in the RWHOIS dictionary.
            :raw_referral: Raw referral whois results if the inc_raw parameter
                is True. (String)
        """

        # Create the return dictionary.
        results = {
            'query': self._net.address_str,
            'nets': [],
            'raw': None,
            'referral': None,
            'raw_referral': None
        }

        # The referral server and port. Only used if get_referral is True.
        referral_server = None
        referral_port = 0

        # Only fetch the response if we haven't already.
        if response is None or (not is_offline and
                                asn_data['asn_registry'] is not 'arin'):

            log.debug('Response not given, perform WHOIS lookup for {0}'
                      .format(self._net.address_str))

            # Retrieve the whois data.
            response = self._net.get_whois(
                asn_registry='jpnic',
                server = 'whois.nic.ad.jp',
                retry_count=retry_count,
                encoding='iso-2022-jp',
            )

        if inc_raw:

            results['raw'] = response

        nets = []

        nets_response = self._get_nets_jpnic(response)

        nets.extend(nets_response)

        # Iterate through all of the network sections and parse out the
        # appropriate fields for each.
        log.debug('Parsing WHOIS data')
        for index, net in enumerate(nets):

            section_end = None
            if index + 1 < len(nets):

                section_end = nets[index + 1]['start']

            try:

                dt_format = RIR_WHOIS[results['asn_registry']]['dt_format']

            except KeyError:

                dt_format = None

            temp_net = self._parse_fields(
                response,
                RIR_WHOIS['jpnic']['fields'],
                section_end,
                net['end'],
                dt_format,
                field_list
            )

            # Merge the net dictionaries.
            net.update(temp_net)

            # The start and end values are no longer needed.
            del net['start'], net['end']

        # Add the networks to the return dictionary.
        results['nets'] = nets

        return results
