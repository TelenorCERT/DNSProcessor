#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
from ConfigParser import SafeConfigParser
import codecs
import time
import json
import dns.query
import dns.zone
import dns.rdatatype
import dns.rdataclass
import dns.resolver
import dns.reversename
import dns.exception

class DNSParser:
    def __init__(self):
        """Class used to perform a DNS zone transfer.
        
        Use to perfom DNS zone transfers on all zones in configuration file and convert the results
        into JSON format.

        Attributes:
            DOMAINS (list): List of domains from config file to perform zone transfer on.
            DOMAINS_DICT (dict): Dictionary with all information from config file.
        Raises:
            ValueError: If configuration file contains no domains.

        Examples:
            >>> DNSParser = DNSProcessor.DNSParser()                                            
            >>> dns_zones = DNSParser.transfer_zones()                                          
            >>> DNSParser.build_json(dns_zones, OUTPUT_FILE)                                    
        """
        #Read config
        parser = SafeConfigParser()

        with codecs.open('dns.ini', 'r', encoding='utf-8') as f:
            parser.readfp(f)

        self.DOMAINS = parser.sections()
        if len(self.DOMAINS) == 0:
            error_msg = u'Config file contains no domain information.\n'
            raise ValueError(error_msg)

        self.DOMAINS_DICT = {}
        for domain in self.DOMAINS:
            name_server = parser.get(domain, 'name_server')
            source = parser.get(domain, 'source')
            source_type = parser.get(domain, 'source_type')
            source_value = parser.get(domain, 'source_value')
            
            self.DOMAINS_DICT[domain] = {'name_server': name_server, 'source': source, 
                'source_type': source_type, 'source_value': source_value}

    def transfer_zones(self):
        """Performs a zone transfer on all DNS zones in configuration file.
        
        Returns:
            dns_zones (list): List of tuples with domain and zone transfer.
        """
        dns_zones = []
        for domain in self.DOMAINS_DICT.iterkeys():

            try:
                z = dns.zone.from_xfr(dns.query.xfr(
                    self.DOMAINS_DICT[domain]['name_server'], domain))
                dns_zones.append((unicode(domain), z))
            except dns.query.UnexpectedSource, e:
                print('DNS query response from an unexpected address or port: ' + e.args[1])
            except dns.query.BadResponse, e:
                print('DNS query response does not respond to the question asked: ' + e.args[1])
        
        return dns_zones

    def build_json(self, dns_zones, output):
        """Converts zone transfer results from list to JSON files.

        Converts the zone transfer results from a list of tuples with domain and dns zones into 
        JSON unicode output. One file is written to disk per domain.

        Args:
            dns_zones (list): List of tuples with domain and zone transfer.
            output (str): Path to output file.

        Raises:
            ValueError: If dns_zones are empty.
            ValueError: If output file is not a file.
        """
        if dns_zones == None or dns_zones == "":
            error_msg = u'Received no results to write too file.'
            raise ValueError(error_msg)
        
        if os.path.isdir(output):
            error_msg = u'Output file is a directory, needs filename.'
            raise ValueError(error_msg)
        
        for domain, zone in dns_zones: 
            file_name, ext = os.path.splitext(output)
            output_ext = file_name + '-' + domain + '-dns' + ext
            
            f = codecs.open(output_ext, "w", "utf-8")
            os.chmod(output_ext, 0440)
            
            for name, node in zone.iteritems():
                rdatasets = node.rdatasets
                name = unicode(name)

                json_output = {} 
                current_time = unicode(time.mktime(time.localtime()))

                json_output['extractTime'] = current_time
                json_output['datasource'] = self.DOMAINS_DICT[domain]['source']
                json_output['datasource_type'] = self.DOMAINS_DICT[domain]['source_type']
                json_output['datasource_value'] = self.DOMAINS_DICT[domain]['source_value']
                json_output['name'] = name
                json_output['domain'] = domain
                if name != '@':
                    json_output['fqdn'] = name + u'.' + domain
                rdata_output = []
                
                for rdataset in rdatasets:
                    rdclass = dns.rdataclass.to_text(rdataset.rdclass)
                    rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                    ttl = rdataset.ttl
                
                    rdata_json = {}
                    rdata_json['class'] = unicode(rdclass)
                    rdata_json['type'] = unicode(rdtype)
                    rdata_json['ttl'] = unicode(ttl) 
                    
                    if rdtype == 'A' or rdtype == 'AAAA':
                        rdata_json['rdata'] = self.parse_a_record(rdataset)
                    elif rdtype == 'MX':
                        rdata_json['rdata'] = self.parse_mx_record(rdataset)
                    elif rdtype == 'SOA':
                        rdata_json['rdata'] = self.parse_soa_record(rdataset)
                    elif rdtype == 'NAPTR':
                        rdata_json['rdata'] = self.parse_naptr_record(rdataset)
                    elif rdtype == 'TXT' or rdtype == 'SPF':
                        rdata_json['rdata'] = self.parse_txt_record(rdataset)
                    elif rdtype == 'CNAME':
                        rdata_json['rdata'] = self.parse_cname_record(rdataset)
                    elif rdtype == 'SRV':
                        rdata_json['rdata'] = self.parse_srv_record(rdataset)
                    elif rdtype == 'NS':
                        rdata_json['rdata'] = self.parse_ns_record(rdataset)
                    elif rdtype == 'SSHFP':
                        rdata_json['rdata'] = self.parse_sshfp_record(rdataset)
                    else:
                        error_msg = u'Record type ' + unicode(rdtype) + \
                            u' not supported. Please revise script.\n'
                        print(error_msg)
                    
                    rdata_output.append(rdata_json)
                
                json_output['rdatasets'] = rdata_output
                json.dump(json_output, f, indent=4, separators=(',', ': '), ensure_ascii=False, 
                    sort_keys=True)
                f.write('\n')
            f.close()

    def parse_a_record(self, rdataset):
        """Parses rdatasets of type A and AAAA.

        Args:
            rdataset (rdataset): rdataset of type A or AAAA.

        Returns:
            a_record_output (list): List of dictionaries with A or AAAA results and the 
            corresponding PTR record.
        """
        a_record_output = []
        for rdata in rdataset:
            address = rdata.address
            a_record_json = {}
            a_record_json['address'] = unicode(address)
            
            #Check PTR
            try:
                reverse_addr = dns.reversename.from_address(address)
                reverse_result = dns.resolver.query(reverse_addr, rdtype='PTR')
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoNameservers:
                continue
            except dns.resolver.Timeout:
                continue
            
            #Convert PTR and PTR server to JSON
            ptr_rdataset = reverse_result.rrset.to_rdataset()
            ptr_record_output = []
            for ptr_rdata in ptr_rdataset:
                ptr_record_output.append(unicode(ptr_rdata.target))
            a_record_json['ptr'] = ptr_record_output
            
            a_record_output.append(a_record_json)
        return a_record_output
    
    def parse_mx_record(self, rdataset):
        """Parses rdatasets of type MX.

        Args:
            rdataset (rdataset): rdataset of type MX.

        Returns:
            mx_record_output (list): List of dictionaries with MX record results.
        """
        mx_record_output = []
        for rdata in rdataset:
            mx_record_json = {}
            mx_record_json['exchange'] = unicode(rdata.exchange)
            mx_record_json['preference'] = unicode(rdata.preference)
            mx_record_output.append(mx_record_json)
        return mx_record_output
    
    def parse_soa_record(self, rdataset):
        """Parses rdatasets of type SOA.

        Args:
            rdataset (rdataset): rdataset of type SOA.

        Returns:
            soa_record_output (list): List of dictionaries with SOA record results.
        """
        soa_record_output = []
        for rdata in rdataset:
            soa_record_json = {}
            soa_record_json['expire'] = unicode(rdata.expire)
            soa_record_json['minimum'] = unicode(rdata.minimum)
            soa_record_json['mname'] = unicode(rdata.mname)
            soa_record_json['refresh'] = unicode(rdata.refresh)
            soa_record_json['retry'] = unicode(rdata.retry)
            soa_record_json['rname'] = unicode(rdata.rname)
            soa_record_json['serial'] = unicode(rdata.serial)
            soa_record_output.append(soa_record_json)
        return soa_record_output
    
    def parse_naptr_record(self, rdataset):
        """Parses rdatasets of type NAPTR.

        Args:
            rdataset (rdataset): rdataset of type NAPTR.

        Returns:
            naptr_record_output (list): List of dictionaries with NAPTR record results.
        """
        naptr_record_output = []
        for rdata in rdataset:
            naptr_record_json = {}
            naptr_record_json['flags'] = unicode(rdata.flags)
            naptr_record_json['order'] = unicode(rdata.order)
            naptr_record_json['preference'] = unicode(rdata.preference)
            naptr_record_json['regexp'] = unicode(rdata.regexp)
            naptr_record_json['replacement'] = unicode(rdata.replacement)
            naptr_record_json['service'] = unicode(rdata.service)
            naptr_record_output.append(naptr_record_json)
        return naptr_record_output
    
    def parse_txt_record(self, rdataset):
        """Parses rdatasets of type TXT and SPF

        Args:
            rdataset (rdataset): rdataset of type TXT or SPF.

        Returns:
            txt_record_output (list): List of dictionaries with TXT or SPF record results.
        """
        txt_record_output = []
        for rdata in rdataset:
            string_list = []
            for s in rdata.strings:
                string_list.append(unicode(s))
            txt_record_output.append(string_list)
        return txt_record_output
    
    def parse_cname_record(self, rdataset):
        """Parses rdatasets of type CNAME.

        Args:
            rdataset (rdataset): rdataset of type CNAME.

        Returns:
            cname_record_output (list): List of dictionaries with CNAME record results.
        """
        cname_record_output = []
        for rdata in rdataset:
            cname_record_output.append({'target': unicode(rdata.target)})
        return cname_record_output
    
    def parse_srv_record(self, rdataset):
        """Parses rdatasets of type SRV.

        Args:
            rdataset (rdataset): rdataset of type SRV.

        Returns:
            srv_record_output (list): List of dictionaries with SRV record results.
        """
        srv_record_output = []
        for rdata in rdataset:
            srv_record_json = {}
            srv_record_json['port'] = unicode(rdata.port)
            srv_record_json['priority'] = unicode(rdata.priority)
            srv_record_json['target'] = unicode(rdata.target)
            srv_record_json['weight'] = unicode(rdata.weight)
            srv_record_output.append(srv_record_json)
        return srv_record_output
    
    def parse_ns_record(self, rdataset):
        """Parses rdatasets of type NS.

        Args:
            rdataset (rdataset): rdataset of type NS.

        Returns:
            target_records (list): List of dictionaries with NS record results.
        """
        target_records = []
        for rdata in rdataset:
            target_records.append(unicode(rdata.target))
        return [{'target': target_records}] 
    
    def parse_sshfp_record(self, rdataset):
        """Parses rdatasets of type SSHFP.

        Args:
            rdataset (rdataset): rdataset of type SSHFP.

        Returns:
            sshfp_record_output (list): List of dictionaries with SSHFP record results.
        """
        sshfp_record_output = []
        for rdata in rdataset:
            sshfp_record_json = {}
            sshfp_record_json['algorithm'] = unicode(rdata.algorithm)
            sshfp_record_json['fingerprint'] = rdata.fingerprint.encode('hex')
            sshfp_record_json['fp_type'] = unicode(rdata.fp_type)
            sshfp_record_output.append(sshfp_record_json)
        return sshfp_record_output
