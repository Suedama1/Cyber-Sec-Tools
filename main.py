# Imports
from nmap_scanner import nmap_scan
from custom_packet import send_custom_pkt

# Main menu function
def menu():
    """Displays the main menu
    """
    try:
        print("-----------------------------")
        print("** PSEC Info Security Apps **")
        print("-----------------------------")
        # Request user input for the menu option
        getInput = int(input(
            "1) Scan network\n2) Upload/download file using FTP\n3) Send custom packet\n4) Quit\n>> "))
        # If the user selects option 1 run the nmap scan
        if getInput == 1:
            nmap_scan()
        # If the user selects option 3 display the custom packet menu
        elif getInput == 2:
            send_custom_pkt()
        
        # If the user selects option 4 exit the program
        elif getInput == 3:
            exit()
        # If the user selects an invalid option print an error message
        else:
            print("Please enter an valid option.")
    # If the user enters an invalid input print an error message
    except ValueError:
        print("Invalid Input. Please enter an integer.")
    menu()


menu()
