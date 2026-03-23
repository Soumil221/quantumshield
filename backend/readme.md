PNB hackathon Prototype
Just a skeleton for the backend

HOW TO RUN:
cd backend
source .venv/bin/activate 
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

IT requires nmap and subfinder on your system so download it first

The api calls only require the domain
For example :
    {"domain":"youtube.com"}
The various api calls urls are:
/discover
/scan-tls (uses / discover in background)
/cbom (uses / scan-tls in background)

mongodb is used for storing the results of /cbom (very initial stage of development, not complete yet, future scope is to cache it in mongodb or redis to optimize)

now what to do(what I can think of right now)
1) run all the api calls and see if it lacks anything
2) discuss among team what more to implement
3) implement frontend for these api calls in react/next
4) Implement login feature if required
5) Design a better PPT 
6) prepare for the presentation 
7) you can make any changes you want in this, just dont push it straight to master branch, create a new branch

