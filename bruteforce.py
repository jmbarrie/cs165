import itertools
import string
import timeit
import multiprocessing as mp
from md5_crypt import MD5_Crypt

# 4 $1$hfT7jp2q$ow6neA.QFfVDgosUn8iHS. pw: ozzz
# expected_hash = 'ow6neA.QFfVDgosUn8iHS.'
# given_salt = 'hfT7jp2q'
# 5 $1$hfT7jp2q$aYpLSp4GuGa1n5QzJridw1 pw: lzzzz
# expected_hash = 'aYpLSp4GuGa1n5QzJridw1'
# given_salt = 'hfT7jp2q'

# Group hash/salt
expected_hash = 'OLu9dBx9tpySzHymYkmIg1'
given_salt = '4fTgjp6q'

solution = '$1$' + given_salt + '$' + expected_hash
num_processes = 10
max_password_length = 6
alphabet = string.ascii_lowercase
hash_output = ''
start = None

def generate_passwords():
    print('Generating password list')
    start = timeit.default_timer()
    passwords = []
    for i in range(0, max_password_length + 1):
        for x in itertools.product(alphabet, repeat=i):
            passwords.append("".join(x))

    end = timeit.default_timer()
    print('Password list generated')
    print('Password list generated in: ', end - start)

    return passwords

def brute_force(pool, password_list):
    partition = len(password_list) // num_processes

    def callback(result):
        if result:
            print('password cracked')
            print('Output hash: ', hash_output)
            end = timeit.default_timer()
            print('password cracked in: ', end - start)
            pool.terminate()

    print('Starting brute force')
    start = timeit.default_timer()
    for i in range(0, num_processes):
        print(i)
        if i == num_processes - 1:
            work_split = password_list[partition * i:]
        elif i == 0:
            zero_partition = password_list.index('bebwjr')
            print('bebwjr index: ', zero_partition)
            zero_split = (partition * i) + zero_partition
            work_split = password_list[zero_split: partition * (i + 1)]
        else:
            work_split = password_list[partition * i: partition * (i + 1)]

        pool.apply_async(do_job, (work_split, given_salt), callback=callback)

def do_job(work, salt):
    for i in work:
        # print('Attempting password: ', i)
        md5 = MD5_Crypt(i, salt, max_password_length)
        output = md5.get_hash()
        # print('Full output: ', output)
        if output == solution:
                
            cracked_password = i
            hash_output = output
            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            print('Password cracked: ', i)
            print('etc/shadow hash calculated: ', hash_output)
            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            return True 
    
if __name__ == "__main__":
    password_list = generate_passwords()
    my_pool = mp.Pool(processes=num_processes)
    brute_force(my_pool, password_list)
    print(hash_output)
    my_pool.close()
    my_pool.join()