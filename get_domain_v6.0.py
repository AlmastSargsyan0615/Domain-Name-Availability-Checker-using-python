import csv
import concurrent.futures
import itertools
from string import ascii_lowercase
import time
import whois
import os
import validators
import sys
import random
import traceback
from tqdm import tqdm
#This is get_domain_V4.0 file.
#This is get_domain_V4.0 file.
#This is get_domain_V4.0 file.
def menu():
    print("""
           _____          __               
          /  _  \_______ |__| ____   ____  
         /  /_\  \_  __ \|  |/ __ \ /    \ 
        /    |    \  | \/|  \  ___/|   |  \\
        \____|__  /__/\__|  |\___  >___|  /
                \/   \______|    \/     \/ 
    """)
    operation = None
    global count
    global domains
    global checked_domains
    while operation not in ('1', '2'):
        operation = input("Please choose to continue or start new scraping:"
                          "\n\t1) Continue"
                          "\n\t2) Start New Scraping"
                          "\n> ")
    if operation == "1":
        with open('config.txt', 'r') as config_file:
            lines = config_file.readlines()
            number_of_letters = int(lines[0])
            domain_names_extensions = [dne.strip('\n') for dne in lines[1].split(',')]
            key_word = lines[2].strip('\n')
        domains = generate_domains(number_of_letters, domain_names_extensions, key_word)
        with open('checked_domains.txt', 'r') as checked_domains_file:
            checked_domains = [line.strip('\n') for line in checked_domains_file.readlines()]
        count = len(checked_domains)
    else:
        number_of_letters = ''
        done = False
        while not done:
            try:
                number_of_letters = int(input("Please enter the number of letters: "
                                              "\n> "))
                int(number_of_letters)
                done = True
            except:
                pass
        domain_names_extensions = [domain.strip() for domain in input("Please enter the domain name extensions (separated by commas, i.e: com,org,it): "
                                      "\n> ").split(',')]
        key_word = input("Please enter the keyword on the domain (tap ENTER for nothing)"
                          "\n> ")
        with open('config.txt', 'w') as config_file:
            config_file.write(f'{str(number_of_letters)}\n')
            config_file.write(f'{",".join(domain_names_extensions)}\n')
            config_file.write(f'{str(key_word)}\n')
        count = 1
        domains = generate_domains(number_of_letters, domain_names_extensions, key_word)
        with open('checked_domains.txt', 'w') as checked_domains_file:
            pass
        with open('available_domains.csv', 'w', buffering=1) as csv_file:
            csv_file.write(f"{'Available domains'.upper()}\n")
        add_row_to_csv('domain_dictionary.csv', [f"{'Checked domains'.upper()}", f"{'State'.upper()}"])

def generate_domains(number_of_letters, domain_names_extensions, key_word):
    domains_ = []
    for d_n_e in domain_names_extensions:
        if key_word:
            reps = number_of_letters - len(key_word) + 1
            for domain in map(''.join, itertools.product(ascii_lowercase, repeat=reps)):
                for index in range(len(domain) + 1):
                    domains_.append(f'{domain[:index] + key_word + domain[index:]}.{d_n_e}')
        else:
            for domain in map(''.join, itertools.product(ascii_lowercase, repeat=number_of_letters)):
                domains_.append(f'{domain}.{d_n_e}')
    return domains_

def add_row_to_csv(file_name, new_row):
    """
    Add a new row to the last row of a CSV file.
    
    Args:
    - file_name: The name of the CSV file.
    - new_row: The new row of data to be added.
    
    Returns:
    None
    """
    # Ensure that the file is created if it doesn't exist
    if not os.path.exists(file_name):
        with open(file_name, 'w', newline='') as csv_file:
            pass

    # Read existing rows from the CSV file
    existing_rows = []
    with open(file_name, 'r', newline='') as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            existing_rows.append(row)

    # Append the new row to the list of existing rows
    existing_rows.append(new_row)

    # Write the updated rows to the CSV file
    with open(file_name, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(existing_rows)
def check_domain(domain):
    if domain not in checked_domains:
        global count
        count += 1
        count_ = count
        done = False
        while not done:
            try:
                result = whois.whois(domain.replace('\n', ''))
                if result["domain_name"] != None:
                    done = True
                    print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}')
                    with open('checked_domains.txt', 'a') as checked_domains_file:
                        checked_domains_file.write(f'{domain}\n')
                    add_row_to_csv('domain_dictionary.csv', [f'{domain}', "unfree"])
            except:
                if f'No match for "{domain.upper()}".' in traceback.format_exc():
                    print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}\tfree{available_color}')
                    with open('available_domains.csv', 'a', buffering=1) as csv_file:
                        csv_file.write(f'{domain}\n')
                    with open('checked_domains.txt', 'a') as checked_domains_file:
                        checked_domains_file.write(f'{domain}\n')
                    add_row_to_csv('domain_dictionary.csv', [f'{domain}', "free"])
                    done = True
                elif {domain.upper()} in traceback.format_exc():
                    print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}')
                    done = True
                    with open('checked_domains.txt', 'a') as checked_domains_file:
                        checked_domains_file.write(f'{domain}\n')
                    add_row_to_csv('domain_dictionary.csv', [f'{domain}', "unfree"])
                else:
                    print(traceback.format_exc())
def domain_lookup(domain):
    if domain not in checked_domains:
        global count
        count += 1
        count_ = count
        done = False
        while not done:
            if validators.domain(domain):
                try:
                    dm_info = whois.whois(domain)
                    done = True
                    print(dm_info)
                    if((dm_info.registrar != None) or (dm_info.domain_id != None) or (dm_info.registrar_url != None)  or (dm_info.status != None)  or (dm_info.creation_date != None) 
                         or (dm_info.name_servers != None)  or (dm_info.expiration_date != None)) : 
                        print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}\tTaken Domain')
                        with open('checked_domains.txt', 'a') as checked_domains_file:
                            checked_domains_file.write(f'{domain}\n')

                        add_row_to_csv('domain_dictionary.csv', [f'{domain}', "Taken Domain"])
                    else:
                        print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}\tavailable{available_color}')
                        with open('available_domains.csv', 'a', buffering=1) as csv_file:
                            csv_file.write(f'{domain}\n')
                        with open('checked_domains.txt', 'a') as checked_domains_file:
                            checked_domains_file.write(f'{domain}\n')
                        add_row_to_csv('domain_dictionary.csv', [f'{domain}', "available"])
                        done = True

                except:
                    print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}\tavailable{available_color}')
                    with open('available_domains.csv', 'a', buffering=1) as csv_file:
                        csv_file.write(f'{domain}\n')
                    with open('checked_domains.txt', 'a') as checked_domains_file:
                        checked_domains_file.write(f'{domain}\n')
                    add_row_to_csv('domain_dictionary.csv', [f'{domain}', "available"])
                    done = True

            else:
                print(f'\n[{count_}/{len(domains)}]\t[{(count_/(len(domains)+1))*100:.2f} %]\t{domain}\tinvalid')
                done = True
                with open('checked_domains.txt', 'a') as checked_domains_file:
                    checked_domains_file.write(f'{domain}\n')
                add_row_to_csv('domain_dictionary.csv', [f'{domain}', "invalid"])

available_color = '\033[92m'
checked_domains = []
count = None
domains = []

menu()

try:
    print("Starting to check the generated domains in 5 secs.......")
    time.sleep(5)
    list_domains_to_check = domains
    start_index = 0
    end_index = 100
    coff = 100
    j = 0

    for i in range(len(list_domains_to_check)):
        # domain_lookup("toolify.ai")
        domain_lookup(list_domains_to_check[i])
#     # for i in range(len(list_domains_to_check)):
#     #     if (i % coff) == 0:
#     #         start_index = j * coff
#     #         end_index = (j + 1) * coff
#     #         if end_index > len(list_domains_to_check):
#     #             end_index = j * coff + (len(list_domains_to_check) % coff)

#     #         with concurrent.futures.ThreadPoolExecutor() as executor:
#     #                 executor.map(check_domain, list_domains_to_check[start_index:end_index])
#     #                 executor.shutdown(wait=True)
#     #         j = j + 1

#     #  for i in tqdm(range(len(list_domains_to_check)), unit=" domains", ncols=150, desc="Percent of the checked domains", colour="blue"):
#     #     if (i % coff) == 0:
#     #         start_index = j * coff
#     #         end_index = (j + 1) * coff
#     #         if end_index > len(list_domains_to_check):
#     #             end_index = j * coff + (len(list_domains_to_check) % coff)

#     #         with concurrent.futures.ThreadPoolExecutor() as executor:
#     #                 executor.map(domain_lookup, list_domains_to_check[start_index:end_index])
#     #                 executor.shutdown(wait=True)
#     #         j = j + 1
except KeyboardInterrupt:
    print(traceback.format_exc())
except:
    print(traceback.format_exc())
