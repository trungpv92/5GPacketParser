__version__ = "1.0.1"

import argparse
from scapy.layers.inet import IP
from scapy.layers.sctp import SCTP
from scapy.all import rdpcap
from pycrate_asn1dir import NGAP
import time, csv

def parse_arguments():
    parser = argparse.ArgumentParser(description="5G Packet Parser")
    parser.add_argument("--input", required=True, help="Path to input pcap file")
    parser.add_argument("--output", required=True, help="Path to output CSV file")
    parser.add_argument("--packetcount", type=int, default=0, 
                        help="Number of packets to process (default: 0 that means all packets)")
    parser.add_argument("--windowtime", type=float, default=1.0, 
                        help="Time window for packet capture in seconds (default: 1.0)")   
    return parser.parse_args()

def asn1_to_tuple(asn1_obj):
    if hasattr(asn1_obj, 'to_tuple'):
        return asn1_obj.to_tuple()
    elif hasattr(asn1_obj, 'get_name'):  # Handle CHOICE
        choice_name = asn1_obj.get_name()
        choice_value = asn1_obj[choice_name]
        return {choice_name: asn1_to_tuple(choice_value)}
    elif isinstance(asn1_obj, list):  # Handle SEQUENCE OF or SET OF
        return [asn1_to_tuple(item) for item in asn1_obj]
    else:
        return asn1_obj.get_val() if hasattr(asn1_obj, 'get_val') else asn1_obj

def decode_ngap_payload(ngap_payload):
    ngap_pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    try:
        # Decode the NGAP payload
        ngap_pdu.from_aper(ngap_payload)  # Decode with ASN.1 PER format
        ngap_tuple = asn1_to_tuple(ngap_pdu)  # Convert to tuple           
    except Exception as e:
        ngap_tuple = ()
    return ngap_tuple

def write_to_csv(data, filename, mode='w'):
    with open(filename, mode, newline='', encoding='utf-8') as file:
        writer = csv.writer(file) if isinstance(data, list) else csv.DictWriter(file, fieldnames=data.keys())

        if isinstance(data, dict):
            # Write header if overwriting
            if mode == 'w':
                writer.writeheader()
            # Convert dict to rows and write
            writer.writerow(data)
        elif isinstance(data, list):
            writer.writerows(data)
        else:
            raise ValueError("Data should be a list (rows) or dictionary (key-value pairs).")
        
class FeatureExtrator:
    def __init__(self, pcap_file, packet_limit, window_time):
        self.pcap_file = pcap_file
        self.packet_limit = packet_limit
        self.window_time = window_time
        self.start_time = 0       
            
    def run(self):
        # Load PCAP file
        packets = rdpcap(self.pcap_file)

        # Define the desired features here
        RequestMessages = 0
        SuccessfulResponseMessages = 0
        RequestResponseRatio = 0
        RegistrationRate = 0
        PDURequests = 0
        RequestIAT = 0
        ProcedureCodeNumber = 0
        ProcedureCodeRate = 0

        PreviousRequestAT = 0
        TotalRequestAT = 0        

        # Add Feature Description to the first row of the CSV file
        FeatureDescription = ["RequestMessages","SuccessfulResponseMessages","RequestResponseRatio","RegistrationRate","PDURequestRate","RequestIAT","ProcedureCodeNumber","ProcedureCodeRate"]
        FeatureList.append(FeatureDescription)
        
        # Iterate over the packets in the pcap file
        packet_count = 0        
        for packet in packets:
            packet_count += 1
            if packet_count == self.packet_limit + 1 and self.packet_limit != 0:
                break

            if hasattr(packet, 'time'):  # Ensure packet has a time attribute
                timestamp = packet.time  # Unix timestamp
                if packet_count == 0:
                    self.start_time = timestamp
                
                #Calculate Feature Counters when the observation period ends
                if timestamp - self.start_time >= self.window_time:
                    self.start_time = timestamp

                    #Calculate all features
                    if RequestMessages != 0:
                        RequestResponseRatio = format(SuccessfulResponseMessages/RequestMessages,".3f")
                    else:
                        RequestResponseRatio = 0

                    RegistrationRate = format(RequestMessages/self.window_time,".3f")

                    PDURequestRate = format(PDURequests/self.window_time,".3f")

                    if RequestMessages != 0:
                        RequestIAT = format(TotalRequestAT/RequestMessages,".3f")
                    else:
                        RequestIAT = 0

                    ProcedureCodeRate = format(ProcedureCodeNumber/self.window_time,".3f")

                    # Append all feature counters to the FeatureList
                    Features = [RequestMessages,SuccessfulResponseMessages,RequestResponseRatio,RegistrationRate,PDURequestRate,RequestIAT,ProcedureCodeNumber,ProcedureCodeRate]
                    FeatureList.append(Features)

                    # Reset all feature counters
                    RequestMessages = 0
                    SuccessfulResponseMessages = 0
                    RequestResponseRatio = 0
                    RegistrationRate = 0 
                    PDURequests = 0 
                    RequestIAT = 0 
                    ProcedureCodeNumber = 0
                    ProcedureCodeRate = 0

                    PreviousRequestAT = 0
                    TotalRequestAT = 0

            # Process the packet and update Feature Counters
            if packet.haslayer(IP) and packet.haslayer(SCTP):
                self.current_time = packet.time
                sctp_packet = packet[IP][SCTP]  # Extract SCTP layer
                # Iterate over each chunk in the SCTP payload
                current_chunk = sctp_packet.payload
                while current_chunk:
                    if hasattr(current_chunk, "type"):
                        # Check for DATA chunk
                        if current_chunk.type == 0x00:  # Type 0x00 is DATA chunk
                            # Decode the NGAP payload using Pycrate
                            decoded_NGAP = decode_ngap_payload(bytes(current_chunk.data))
                            if decoded_NGAP: #Return Tuple is not empty
                                #Update the total number of Procdure Code
                                ProcedureCodeNumber += 1

                                if decoded_NGAP[1]['procedureCode'] == 15:
                                    if decoded_NGAP[0] == 'initiatingMessage':
                                        #print(decoded_NGAP[0],"\n") 
                                        RequestMessages += 1

                                        #Update the total request AT
                                        if PreviousRequestAT != 0:
                                            TotalRequestAT += timestamp - PreviousRequestAT
                                        PreviousRequestAT = timestamp                                
                                        
                                if decoded_NGAP[1]['procedureCode'] == 14:
                                    if decoded_NGAP[0] == 'successfulOutcome':
                                        #print(decoded_NGAP[0],"\n") 
                                        SuccessfulResponseMessages += 1

                                if decoded_NGAP[1]['procedureCode'] == 29:
                                    if decoded_NGAP[0] == 'initiatingMessage':
                                        #print(decoded_NGAP[0],"\n") 
                                        PDURequests += 1

                    # Move to the next chunk in the SCTP packet
                    current_chunk = current_chunk.payload

        print(f"\nThere are ",packet_count," packets have been successfully processed!")
        

if __name__ == "__main__":

    args = parse_arguments()
    
    # Make a list to store feature values
    FeatureList = []
    
    print(f"\n\n5G Packet Parser is processing the input pcap file...")

    # Create an instance of PacketParser and run it
    # NOTE: packet_limit indicates the number of parsing packets counted from the 1st packet in the pcap file
    # NOTE: set packet_limit = 0 means all packets will be parsed
    start_time = time.time()
    featurefinder = FeatureExtrator(args.input, packet_limit=args.packetcount, window_time=args.windowtime)
    featurefinder.run()
    end_time = time.time()

    write_to_csv(FeatureList, args.output)

    execution_time = end_time - start_time
    print(f"\nTotal Execution Time: {execution_time:.3f} seconds")
