import argparse # To work wih terminal/command line

def encrypt(shellcode, key):
    """ 
    Docstring for encrypt

    :param shellcode: Description : Raw content of the input file ( binary or text format)
    :param  key:  XOR key 
    :return: Encrypted bytes
    """
    encrypted = bytearray() # byte array where encrypted bytes will be stored
    
    try:

        if key.startswith("0x"):
            val = int(key, 16) #convert `str` to integer
            if not (0 <= val <= 0xFF):
                raise ValueError("Hex key must be 1 byte")
            key = bytes ([val]) #convert  bytes

        else: # multi-byte key   
            key = key.encode ("utf-8")

    except Exception as e:
        raise ValueError("Invalid key") from e

    # Iterate over the shellcode content and encrypt it using XOR
    try:

        for i in range (len(shellcode)):
            result = shellcode[i] ^ key[i % len(key)] # If multi-byte key is used, loop back to the beginning of the key
            encrypted.append(result) # Add encrypted byte to the array
    except Exception as e:
        raise RuntimeError ("Error during encryption") from e

    return encrypted # Bytes(encrypted)


def parser_python(encrypted):
    """
    Docstrings for parser_python

    :param encrypted :Bytes encrypted

    :returns: Python array
    """
    result = "buf=["
    for b in encrypted:
        result += f"0x{b:02x}, " # Byte in hexadecimal with two digits ( that is why 02)
    result = result[:-2]    # Remove the last comma and space
    result += "]"    
    return result

def parser_c(encrypted):

    """
    Docstrings for parser_c

    :param encrypted :Bytes encrypted

    :returns: C array
    """
    result = "unsigned char buf[] = {"
    for b in encrypted:
        result += f"0x{b:02x}, " # Byte in hexadecimal with two digits ( that is why 02)
    result = result[:-2]    # Remove the last comma and space
    result += "};"    
    return result

    

def parser_raw(encrypted):  
  
    """
    Docstrings for parser_raw

    :param encrypted: Bytes encrypted

    :return: raw bytes 
    """    
    return encrypted



def main():

    """
    Main function
        
    Create parser and arguments:
    --in: Input file
    --out: Output file
    --key: XOR key
    --format: output format
    """

    parser = argparse.ArgumentParser()

    parser.add_argument("--in",  dest="input_file",required=True,help = "input file to encrypt" )
    parser.add_argument("--out",  dest= "output_file",required=True,help="output file encrypted" )
    parser.add_argument("--key",  dest= "key" ,required=True, help = "key 1 byte or multi")
    parser.add_argument("--format",  dest= "format" ,required=True, choices=["raw","python","c"], help = "raw,python or c")

    args = parser.parse_args() # Retrieve values passed via command line

    try: 
        # Check if input/output files can be opened correctly
        # 1 Open input file
        with open(args.input_file,"rb") as f: # rb because input file is binary
            shellcode = f.read() # Read file content

            # 2 Encrypt shellcode content
            encrypted = encrypt(shellcode, args.key)
            
            # 3 Print output in requested format
            if args.format == "python":
                print( parser_python(encrypted))
            elif args.format == "c":
                print(parser_c(encrypted))
            else:
                print(parser_raw(encrypted))
        
            # Save encrypted content to output file
            with open (args.output_file, "wb") as of:
                of.write (encrypted)

    except FileNotFoundError as e:
        # Error if the specified input file does not exist
        print("Error reading file:", e)

    except Exception as e:
        # Handle any other unexpected error
        print("Unexpected error:", e)            

if __name__== "__main__":
    main()       