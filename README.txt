The Secure Messaging Application

Technologies:
    - Frontend: HTML, BulmaCSS, JavaScript
    - Backend: Go
    - Database: SQLite
    - Cryptography Algorithms: DES, ECC, SHA-1

Run:
    - Navigate to "server" directory
    - Install necessary dependencies: go get <dependency-link>
    - Execute: go run .
    - After that go to localhost:8080 url in your browser.


Overview:

The Application uses websockets for communication. First you have to register using a username and a password. After that,
navigate to the sign in tab and enter your username and password to log in. Your username will be stored in the session storage
of the browser. After sign in you will see the chat interface. You can send messages to users that is registered for the
application.

If user you are sending the message is not online, it is ok. All the messages are store in the database. So when that user log
in, he can view the past messages.


Security:

We use 3 cryptographic algorithms in this application. Namely DES, ECC and SHA-1. We use SHA-1 to hash passwords of the users. When
you register for the first time your password will be hashed and store in the database. For Key Exchange we use ECC algorithm. The shared
secret generated using the ECC algorithm will use as the key for the DES algorithm which we use to encrypt the messages. The shared Key
that use to encrypt the messages will store in the database so we can use the old shared keys to decrypt the message history.


Future Improvements:

The user interface is kinda ugly right now and also the user experience need to improve. The algorithms we used here are not very safe.
So We have to implement more secure algorithms. especially for password hashing. Furthermore, We need to find a better way to handle user
sessions.


Overall, We enjoyed making this application. It was painful sometimes specially when dealing with padding and key exchange, but the
overall experience was not bad. We able to learn about cryptography, websockets, http requests, json parsing and few more things. 
We able to learn the go language which is also a completely new experience.