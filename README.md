# SSRA

This is a proof of concept for the *SSRA: A Secure Social Robot Architecture* project.

## Run it with Docker
- Compile the app: `cd ssra; docker build -t ssra .`
- Run it: `docker run -v ./shared:/usr/src/myapp/shared -it --rm --name running-ssra ssra <role>`

Possible roles:
- `tutor`: generates master keys and a user key
- `robot`: encrypt a sample content with two attributes 
- `user`: read and decrypt the encrypted content 
