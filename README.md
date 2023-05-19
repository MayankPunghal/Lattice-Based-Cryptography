# Lattice-Based-Cryptography
Understanding and implementation of lattice based cryptography
# Abstract
Among different cryptosystems, the public key cryptosystems are of great importance as they can be used in a wide number of applications. However, there has been a lot of progress in the field of quantum computing. Techniques such as RSA, AES are hard to break using classical computation but it could easily be decrypted using quantum computing, putting our data security at risk. Using quantum computing, it may be too easy to decrypt information. Lattice based cryptography could be one of the important cryptography techniques that can be resistant to quantum attacks. NTRU requires low memory. Moreover, it’s keys are short and easily generated. In this paper, we discuss about lattice-based cryptosystem, its implementation (using NTRU) and some applications where lattice-based cryptography could be useful. NTRU key generation, encryption and decryption has been explained.

# Introduction
Sensitive data on computer systems is prone to unauthorized access with the advancement in technology, risking the data security of our systems. With the advances in technology and quantum computer generation, threats of cryptanalytic attacks will pose a serious impact on our computer security, thereby making conventional cryptographic schemes obsolete [1]. To prevent these circumstances, we need to improve upon our cryptographic algorithms and security protocols. Our current systems use mathematical problems as their base (for example RSA Algorithm, Diffie Hellman exchange protocol and elliptic curve cryptography).These problems are considered to be unsolvable by conventional computers in polynomial time. However, with the introduction of quantum computation, it is easy to undermine these algorithms (like Rivest–Shamir– Adleman ) which were impossible to decrypt with the conventional computational power, thus risking our information. 
 The advent of quantum computers undermines the security of these current widely used asymmetric algorithms. Shor's algorithm demonstrated that both factoring and discrete logarithm problems are solvable on a quantum computer [2] (Shor’s algorithm was able to factor a given integer ‘N’ into its prime factors in polynomial time). So, scientists have tried to develop methods based on Lattice Based Cryptography which are way more secure, moreover, it would be difficult even for quantum computers to be able to decrypt those Lattice Cryptographic Algorithms. It is expected that classical computing will be replaced by quantum computing which would pose a major threat to the current security protocols in place. 
To prevent the repercussions of what quantum computers will be able to do in near future, we can use some other similar unsolvable mathematical problems one such problem being Lattice Based asymmetric problem. Forming a Lattice based cryptic algorithm has been a major area of research in post-quantum computing era.

# Literature review
Lattice is an infinite arrangement of equidistant points in a vector space. Since it is infinite, and a computer does not have infinite memory, we use basis. A basis vector (usually linearly independent vectors) can be used to form whole Lattice. Lattices having same basis are equivalent.
 
This is the mathematical description for one such lattice.

 ![image](https://github.com/MayankPunghal/Lattice-Based-Cryptography/assets/50830003/e56b628c-1342-4bae-ac6d-fcd05d5759a1)

*Figure 1 : Image showing a Lattice*

Lattice based cryptography is basically applied on areas where security of our data is of significant importance. This technique is entirely based on the hardness of the problem. We use problems like shortest vector problem, closet vector problem and SIS problems.
Some other lattice based problems are mentioned below:
 
 ![image](https://github.com/MayankPunghal/Lattice-Based-Cryptography/assets/50830003/6a218c6d-2d88-43da-9536-2702e3bbfb9c)

 
The main issue with classical cryptosystems are that the key size is small for these systems. Moreover, there are loopholes in these techniques. Suppose someone transmitting information without the use of OTP, a person with good knowledge of cryptographic techniques could easily have access to the information. With the use of lattice based cryptography, it could be a very difficult task even for quantum computers to have access without the knowledge of the key. Computation speed of lattice based cryptosystems is higher than that of classical cryptosystems.
GGH and NTRU are commonly used cryptosystems. While GGH is an asymmetric and based on closest vector problem, NTRU is a cryptosystem that is based on shortest vector problems. Both the problems are of significant difficulty. Lattice based cryptography can be used in digital signatures. 
Lattice based Cryptography has various applications in our day to day life. Using IOT is at risk due to advancement of quantum computing. It could help the attacker to attack on devices. The security would be a problem. So Lattice based cryptography could be used as it is highly efficient and safe from the quantum computing. We could apply any of the hard problems in the system. But actually finding these hard problems is not easy. Also, more number of keys are required. In order to resolve these issues, Lattice based cryptography could be used.
It could be used in several fields where we need to provide efficient and advanced security. It could be used in medical implants and on military grounds, like where and when to hit the target with missile and monitoring the vital signs or the performances of those medical implants, as this information needs advanced security.
Although in all these fields, both classic cryptography and lattice based cryptography could be used, lattice based cryptography should be used as these fields require high security levels. 
Email is one of the least encrypted mode of communication. People generally care less about its encryption as not much confidential information is sent using emails. Lattice based cryptography can be applied on emails in case it is being used for military information sharing or when the matter affects the national security. Although email is not preferred for this type of information sharing. It can also be used in file sharing applications.
Since this is the era of electronic payments, the security entirely depends on encryption standards. Frauds during electronic payments would be very less if we use better encryption standards. Hackers won’t be able to gain access to the information. So, Lattice based cartography can be used in electronic payments as well.
It can  also be used in disk encryption. Disk encryption is basically the process of hiding information from illegitimate users by converting it to unreadable code. A password based authentication is required to access the information on the disk.
An anonymous remailer is a service which receives messages with the information about were to forward it but it does not disclose the original sender of the email. It is not possible for the receiver to retrace the original sender of the message. Lattice based cryptography can be used in such scenarios.
There can be various other innumerable applications where Lattice Based Cryptography exceeds every other algorithm in terms of reliability and security.

# Algorithm

Lattice based cryptography uses general presumed hard to solve lattice problems to set the basis of hardness to crack the cryptosystem’s for example SVP (Shortest Vector Problem), SIVP (Shortest In-dependent Vector Problem), Closest Vector Problem, BDD (Bounded Distance Decoding) etc.
 Some of the recently used cryptosystems are Ring Learning With Error (R-LWE) and NTRU.

We explored the implementation of NTRUEncrypt(Nth Degree Truncated Polynomial Ring Unit).It is basically a lattice based alternative to conventional crypt algorithms like RSA which uses Shortest Vector Problems in lattice.

 Prerequisite: Encryption and decryption is occurring between two parties A and B, presumably A is the sender and B is the receiver. 
Public parameters taken to explain examples :(N, p, q, d) = (7, 3, 41, 2).

![image](https://github.com/MayankPunghal/Lattice-Based-Cryptography/assets/50830003/5fc22db7-69ee-4624-b979-a76d67ea4296)

# NTRU Algorithm:


I.	Key Generation

 1.	The receiver end (User B) is required to choose 2 random polynomials(small) ,f and g from R where R=Z[X]/(X^N-1) such that inverse of   both these polynomials exist and these values must be kept secret.

 2.	Compute inverse (f modulo q) and inverse (f modulo p) using properties:
  1.	f*fq-1 = 1 (modulo q)
  2.	f*fp-1 = 1 (modulo p)

 3.	Compute h=p * ((fq)*g)mod q
  1.	public key for receiver: h
  2. private key for receiver: fg

![image](https://github.com/MayankPunghal/Lattice-Based-Cryptography/assets/50830003/5441e624-4515-43ce-aa08-59b198824398)
*Figure 2 : Key Generation*
