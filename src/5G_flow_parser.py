from scapy.layers.inet import IP
from scapy.layers.sctp import SCTP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader
from scapy.all import sniff
from pycrate_asn1dir import NGAP
from pycrate_mobile import NAS
from pycrate_mobile.NAS import *

class PacketParser:
    def __init__(self, pcap_file, packet_limit):
        self.pcap_file = pcap_file
        self.packet_limit = packet_limit

    def asn1_to_tuple(self, asn1_obj):
        if hasattr(asn1_obj, 'to_tuple'):
            return asn1_obj.to_tuple()
        elif hasattr(asn1_obj, 'get_name'):  # Handle CHOICE
            choice_name = asn1_obj.get_name()
            choice_value = asn1_obj[choice_name]
            return {choice_name: self.asn1_to_tuple(choice_value)}
        elif isinstance(asn1_obj, list):  # Handle SEQUENCE OF or SET OF
            return [self.asn1_to_tuple(item) for item in asn1_obj]
        else:
            return asn1_obj.get_val() if hasattr(asn1_obj, 'get_val') else asn1_obj

    def decode_ngap_payload(self, ngap_payload):
        ngap_pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        try:
            # Decode the NGAP payload
            ngap_pdu.from_aper(ngap_payload)  # Decode with ASN.1 PER format
            ngap_tuple = self.asn1_to_tuple(ngap_pdu)  # Convert to tuple
            #print("\nNGAP Decoded Message (ASN.1) Details:")
            #print(ngap_pdu.to_asn1())            
        except Exception as e:
            print(f"Error decoding NGAP payload: {e}")
        return ngap_tuple
    
    def extract_ngap_ids(self, data: any) -> dict[str, any]:
        results = {'AMF-UE-NGAP-ID': None, 'RAN-UE-NGAP-ID': None}
        def recursive_search(data: any):
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == 'value' and isinstance(value, tuple):
                        # Check if the tuple contains the NGAP ID names
                        if value[0] == 'AMF-UE-NGAP-ID':
                            results['AMF-UE-NGAP-ID'] = value[1]
                        elif value[0] == 'RAN-UE-NGAP-ID':
                            results['RAN-UE-NGAP-ID'] = value[1]
                    elif key == 'aMF-UE-NGAP-ID':
                        results['AMF-UE-NGAP-ID'] = value
                    elif key == 'rAN-UE-NGAP-ID':
                        results['RAN-UE-NGAP-ID'] = value
                    # Recurse into nested structures
                    recursive_search(value)
            elif isinstance(data, (list, tuple)):
                for item in data:
                    recursive_search(item)
        # Start the recursive search from the root of the data
        recursive_search(data)
        return results

    def extract_nas_payload(self, data: any) -> dict[str, any]:
        results = {'NAS-PDU': None}
        def recursive_search(data: any):
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == 'value' and isinstance(value, tuple):
                        # Check if the tuple contains the NGAP ID names
                        if value[0] == 'NAS-PDU':
                            results['NAS-PDU'] = value[1]
                    # Recurse into nested structures
                    recursive_search(value)
            elif isinstance(data, (list, tuple)):
                for item in data:
                    recursive_search(item)
        # Start the recursive search from the root of the data
        recursive_search(data)
        return results
    
    def decode_nas_payload(self, nas_payload):
        try:
            # Decode the NGAP payload
            Msg = NAS.parse_NAS_MO(nas_payload)
            #show(Msg)
        except Exception as e:
            print(f"Error decoding NAS payload: {e}")
        return Msg

    # Function to decode BCD to int
    def decode_bcd(self, bcd_bytes):
        # BCD format uses 2 digits per byte, so we need to unpack accordingly
        decoded_value = ''.join([str((bcd_bytes[i] >> 4) & 0x0F) + str(bcd_bytes[i] & 0x0F) for i in range(len(bcd_bytes))])
        return int(decoded_value)
       
    def process_packet(self, packet, packet_count):
        global NGAP_Flow_List, UE_ID_vs_RAN_UE_ID
        if packet.haslayer(IP) and packet.haslayer(SCTP):
            IP_Src =  packet[IP].src
            IP_Dst = packet[IP].dst

            sctp_packet = packet[IP][SCTP]  # Extract SCTP layer
            print(f"\n\nPacket: {packet_count}")
            print(f"Summary: {packet.summary()}")
            print(f"SCTP Source Port: {sctp_packet.sport}")
            print(f"SCTP Destination Port: {sctp_packet.dport}")

            # Iterate over each chunk in the SCTP payload
            chunk_index = 1
            NGAP_data_index = 0
            current_chunk = sctp_packet.payload
            while current_chunk:
                # Check for DATA chunk
                if current_chunk.type == 0x00:  # Type 0x00 is DATA chunk
                    NGAP_data_index += 1
                    print(f"\n  NGAP DATA {NGAP_data_index}:")
                    print(f"    Payload Protocol Identifier: {current_chunk.proto_id}")

                    # Decode the NGAP payload using Pycrate
                    decoded_NGAP = self.decode_ngap_payload(bytes(current_chunk.data))

                    print(f"    Type: {decoded_NGAP[0]}")
                    print(f"    Message: {decoded_NGAP[1]['value'][0]} with procedureCode: {decoded_NGAP[1]['procedureCode']}")

                    # Find the AMF-UE-NGAP-ID and RAN-UE-NGAP-ID in the decoded data
                    RAN_UE_NGAP_ID = None
                    AMF_UE_NGAP_ID = None
                    NGAP_IDs = self.extract_ngap_ids(decoded_NGAP)
                    print(f"    NGAP IDs:", NGAP_IDs)
                    RAN_UE_NGAP_ID = NGAP_IDs['RAN-UE-NGAP-ID']
                    AMF_UE_NGAP_ID = NGAP_IDs['AMF-UE-NGAP-ID'] 

                    #Process only InitialUEMessage to get EU_ID
                    UE_ID = None
                    if decoded_NGAP[1]['procedureCode'] == 15: 
                        NAS_PDU = self.extract_nas_payload(decoded_NGAP)
                        if NAS_PDU['NAS-PDU'] != None:
                            #print(f"    Decoded NAS-PDU payload:")
                            Decoded_NAS_PDU = self.decode_nas_payload(NAS_PDU['NAS-PDU'])
                            if len(Decoded_NAS_PDU[0]['5GSID'][1].get_val()) == 5:
                                #MSIN data structure
                                byte_data = Decoded_NAS_PDU[0]['5GSID'][1][4][5].get_val()
                                decoded_UE_ID  = decode_bcd(byte_data)
                                print(f"    UE-identity (MSIN):",decoded_UE_ID)   
                                UE_ID = decoded_UE_ID
                            elif len(Decoded_NAS_PDU[0]['5GSID'][1].get_val()) == 8:  
                                #5GS-TMSI data structure                   
                                decoded_UE_ID = Decoded_NAS_PDU[0]['5GSID'][1][7].get_val() 
                                print(f"    UE-identity (TMSI):",decoded_UE_ID)   
                                UE_ID = decoded_UE_ID

                    #Update the UE_ID_vs_RAN_UE_ID dictionary
                    if UE_ID != None and UE_ID not in UE_ID_vs_RAN_UE_ID.keys():
                        UE_ID_vs_RAN_UE_ID[UE_ID] = RAN_UE_NGAP_ID

                    else:
                        NGAP_Flow = [UE_ID,IP_Src,IP_Dst,RAN_UE_NGAP_ID,AMF_UE_NGAP_ID]
                        if NGAP_Flow not in NGAP_Flow_List:
                            NGAP_Flow_List.append(NGAP_Flow)

                # Move to the next chunk in the SCTP packet
                current_chunk = current_chunk.payload
                chunk_index += 1

    #def process_packet(self, packet):
        #print(packet.summary())
            
    def run(self):
        packet_count = 0
        # Iterate over each packet in the PCAP file
        for pkt_data, pkt_metadata in RawPcapReader(self.pcap_file):
            packet = Ether(pkt_data)  # Parse as Ethernet frame
            packet_count += 1
            if packet_count == self.packet_limit + 1 and self.packet_limit != 0:
                break
            # Process the packet if it contains SCTP
            self.process_packet(packet, packet_count)
        
        #sniff(iface="Ethernet 3", filter="tcp", prn=self.process_packet)

if __name__ == "__main__":
    # Define the path to your PCAP file
    pcap_file = "test3_ue1_connection3_acceptedbycore.pcapng"
    #pcap_file = "malicious_deregister_70_10_1_100_1_ngap_Scenario2.pcap"
    
    UE_ID_vs_RAN_UE_ID = {}
    NGAP_Flow_List = []

    # Create an instance of NGAPPacketExtractor and run it
    # NOTE: packet_limit indicates the number of parsing packets counted from the 1st packet in the pcap file
    # NOTE: set packet_limit = 0 means the whole packets will be parsed
    extractor = PacketParser(pcap_file, packet_limit=0)
    extractor.run()

    for flow in NGAP_Flow_List:
        print(flow)

    print("NGAP Flow Number: ",len(NGAP_Flow_List))
