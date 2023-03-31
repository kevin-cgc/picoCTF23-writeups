# Warmup

## Intro

In the warmup for PowerAnalysis, we are given the hamming sum of the lowest bit of the result of the Sbox:
```py
# Leaks one bit of information every operation
leak_buf = []
def leaky_aes_secret(data_byte, key_byte):
    xor = data_byte ^ key_byte
    out = Sbox[xor]
    leak_buf.append(out & 0x01)
    return out
 
[...]

def encrypt_and_leak(plaintext):
    ciphertext = encrypt(plaintext, SECRET_KEY)
    ciphertext = None # throw away result
    time.sleep(0.01)
    return leak_buf.count(1)
```

We are able to fully control the plaintext via user input.

Since there is no noise added to the leaked data, we should be able to deterministically solve for the key, if we know sufficient `plaintext -> leak_count` pairs.

The first two tools I had in mind to solve this problem were Mathematica and the Z3 Theorem Prover.
Both are capable of solving complex systems of equations but, from my experience, Z3 is easier to use for "low-level" (problems involving bitwise, sized integers, etc.) compared to Mathematica which excels with "high-level" (problems involving algebraic, calculus, etc.) problems.
So, given this problem involves bitwise operations with sized integers and does not require any complex algebra or calculus, I decided to pursue a solution in Z3 (I also just wanted to use it more).


## Solution

Here is the essence of the Z3 Solver code, cleaned up for this writeup:

```py
s = Solver() # create the solver
key_vars = [BitVec(f'key_{i}', 8) for i in range(16)] # create 16x 8 bit `key` variables that we we are trying to solve for

Sbox_z3 = Function('Sbox_z3', BitVecSort(8), BitVecSort(8)) # define the Sbox as a 'Function' in Z3

for i in range(256):
    s.add(Sbox_z3(i) == Sbox[i]) # move the entire Sbox into z3 by defining the Sbox_z3 function to be


def add_leakage_constraints(leakage, plaintext_hex): # we run this function whenever we get a `plaintext -> leak_count` pair to insert the constraint into Z3
    pt = bytes.fromhex(plaintext_hex)
    fixed_plaintext_vars = [BitVecVal(b, 8) for b in pt] # create a list of 'constant valued' 8 bit variables that are the plaintext for this pair

	# create the constraint for the key_vars to match the `plaintext -> leak_count` output we got from the server
    leakage_bits = [Sbox_z3(fixed_plaintext_vars[i] ^ key_vars[i]) & 0x01 for i in range(16)]
    s.add(Sum(leakage_bits) == leakage)


def check_solution():
    if s.check() == sat: # if there is a solution, get the model, and extract the key from it.
        # we may not get the right key initially as there could be multiple solutions if the key bytes are underconstrained
        m = s.model()
        key = [m.evaluate(key_vars[i]).as_long() for i in range(16)]
        key_hex = ''.join(f'{x:02x}' for x in key)
        return key_hex
    else:
        return None # if we hit this, we have overconstrained the key and there are no solutions left
```

Now, what plaintexts to send to the server, in order for Z3 to find the correct solution:

```py
# generate plaintext by returning a single 1 bit in all positions
def generate_plaintexts_single_bit():
    yield "00000000000000000000000000000000"
    for i in range(16):
        for o in range(8):
            yield "00" * i + f'{1 << o:02x}' + "00" * (15 - i)

def generate_plaintexts_two_bits():
    for i in range(16):
        for o in range(8):
            for p in range(o + 1, 8):
                yield "00" * i + f'{(1 << o) | (1 << p):02x}' + "00" * (15 - i)


def generate_plaintexts():
    return itertools.chain(generate_plaintexts_single_bit(), generate_plaintexts_two_bits())
```
I initially just had generate_plaintexts_single_bit but found it alone wasn't enough.

This solution is single threaded, and a little slow, but I found it an interesting exercise in using Z3.

---

# Level 2
> I solved Level 1 identically, even using the same plaintext values from L2
## Intro
Now, in Level 2, we are not given a directly leaked value, but instead a list of `plaintext -> "power-consumption trace"` pairs.
We are told that the power consumption is "correlated with the Hamming weight of the bits being processed" and that there is some noise.

Since we are told there is noise, I preferred not to use Z3. In hindsight, I could have probably still used it with soft constraints and/or optimization and I'd like to explore that avenue further.

## Solution

This is the solution script (almost) in full:
```py

def hamming_weight(x):
	return bin(x).count("1")

# def intermediate(pt, key_guess):
# 	return pt ^ key_guess
def intermediate(pt, key_guess):
	return Sbox[pt ^ key_guess]

def correlation_coefficient(x, y):
	return np.corrcoef(x, y)[0, 1]

from multiprocessing import Pool

def cpa_attack_single_byte(tuple):
    (traces, key_byte) = tuple
    num_traces = len(traces)
    trace_length = len(traces[0]["Power trace"])

    max_correlation = -1
    best_guess = None

    print(f"Attacking key byte {key_byte}...")

    for guess in range(256):
        hypothesis = np.zeros(num_traces)

        for tnum, trace in enumerate(traces):
            pt = int(trace["Plaintext"][key_byte * 2:key_byte * 2 + 2], 16)
            st = intermediate(pt, guess)
            hypothesis[tnum] = hamming_weight(st)

        for j in range(trace_length):
            power_trace = np.array([trace["Power trace"][j] for trace in traces])
            correlation = abs(correlation_coefficient(hypothesis, power_trace))

            if correlation > max_correlation:
                max_correlation = correlation
                best_guess = guess

    return f'{best_guess:x}'

def cpa_attack(traces, num_key_bytes=16):
    params = list(zip([traces] * num_key_bytes, range(num_key_bytes)))
    # print(params)
    with Pool(16) as executor:
        key_guess = executor.map(cpa_attack_single_byte, params)

    return key_guess

if __name__ == "__main__":
	trace_directory = "./traces"
	traces = load_traces(trace_directory)
	key_guess = cpa_attack(traces)
	print("Best key guess: ", "".join(key_guess))
  
```

This solution is multithreaded, and runs in ~60-90 seconds on a >16 core cpu (3900X).

The `cpa_attack_single_byte` function is the basis of the attack.
We want to find the `guess` with the highest correlation between the "hamming weight" and the "power-consumption trace" for every pair of `plaintext -> "power-consumption trace"`.
Through some guessing+googling+gpting I realized that the "hamming weight" is probably the hamming weight of the Sbox result.
And to check the correlation to the "power-consumption trace" we actually want to check the correlation between every "hamming weight" and each column of the "power-consumption trace" and just take the one with the highest correlation value.
We then take the guess with the highest correlation value as our best guess for that byte of the key.

In practice the solution is relatively simplistic, but makes a lot of assumptions. Determining what assumptions can be made could be the most difficult part of this challenge.


