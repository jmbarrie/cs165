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
start = None

def generate_passwords():
    print('Generating password list')
    start = timeit.default_timer()
    passwords = []
    # for i in range(0, max_password_length + 1):
        # for x in itertools.product(alphabet, repeat=i):
            # passwords.append("".join(x))
    for x in itertools.product(alphabet, repeat=6):
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
            end = timeit.default_timer()
            print('password cracked in: ', end - start)

    print('Starting brute force')
    start = timeit.default_timer()
    result_obj = []

    for i in range(0, num_processes):
        if i == num_processes - 1:
            work_split = password_list[partition * i:]
        else:
            work_split = password_list[partition * i: partition * (i + 1)]

        result = pool.apply_async(do_job, (work_split, given_salt, solution), callback=callback)
        result_obj.append(result)
    
    for result in result_obj:
        if result.get():
            results = result.get()

    if results:
        print('Results: ', results)
    pool.close()
    pool.join()

def do_job(work, salt, solution):
    for i in work:
        md5 = MD5_Crypt(i, salt, max_password_length)
        output = md5.get_hash()
        if output == solution:
            return i
    
    return False
    
if __name__ == "__main__":
    password_list = generate_passwords()
    my_pool = mp.Pool(processes=num_processes)
    password_list.reverse()
    brute_force(my_pool, password_list)