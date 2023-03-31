# Intro
We are given a RSA implementation that leaks us the private exponent and the ciphertext, 
but not the public modulus, which would normally be required to decrypt the ciphertext.

Here is my labeled version of chal.py:
```py
pride = "".join(choice(ascii_letters + digits) for _ in range(16)) # plaintext
gluttony = getPrime(128) # p
greed = getPrime(128) # q
lust = gluttony * greed # n (public modulus)
sloth = 65537 # e (public exponent)
envy = inverse(sloth, (gluttony - 1) * (greed - 1)) # d (private exponent)

anger = pow(bytes_to_long(pride.encode()), sloth, lust) # c
```

One reference I used was https://hackmd.io/@bauhinia/hitcon2019-lost-modulus-again.
I had a hard time trying to follow it, and was only really able to extract how to find $\phi(n)$ (eulers totient of the public modulus).
Hence, I wanted to document my solution for others who may find it difficult to follow that, and other online references.

# So, what do we actually need for this attack
Required for attack
- e (in this case: 65537)
- c (ciphertext provided by challenge server)
- d (private exponent provided/"leaked" by challenge server)

Not required, but helpful in reducing search space
- Bit size of p and q = 128 (getPrime seems to always returns a prime of exactly 128 bits)

# My version of the attack
- Calculate $k*\phi(n)$:

Since, by definition, d is a solution to $de \equiv 1 (mod \phi(n))$, we can find $k*\phi(n)$ for some integer $k$

![image](https://user-images.githubusercontent.com/58094058/229044598-66f64227-b03c-4191-b5a0-b21f0ac586a4.png)

- Find all divisors of $k*\phi(n)$. That set also contains the divisors of $\phi(n)$: $p-1$ and $q-1$

![image](https://user-images.githubusercontent.com/58094058/229044776-0aa2b8ee-0b55-4900-90e0-31c1fff68359.png)

- Select divisors where $divisor + 1$ is prime AND has a bit length of exactly 128

![image](https://user-images.githubusercontent.com/58094058/229045056-b62c99d6-9b69-4b58-b24f-58d91f353a6f.png)

- Since this is generally a pretty small number of primes (~14), we can just try decrypting the cipher text using each possible pair and filtering by printable ASCII plaintexts

![image](https://user-images.githubusercontent.com/58094058/229045537-ed7b5651-34d6-4e99-adec-65840ea9e027.png)

And thats it!

There are definitely optimizations that can be made in regards to picking p and q pairs, and reducing the number of divisors found in the first place.
Such optimizations are covered in @bauhinia's writeup, such as bounding $k$ to $0 \lt k \lt e$.
However, this solution still runs (nearly) instantly and is hopefully easier to grasp.


# Full Mathematica solution

![image](https://user-images.githubusercontent.com/58094058/229046355-86482c52-368c-4e6f-912e-dd71fb50a27f.png)

