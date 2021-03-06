# **Ransomware**
Ransomware created for CECS 378 at CSULB

Located at: [www.onestyle.tech](www.onestyle.tech)

### **Classroom Resources:**
* [https://blog.cloudboost.io/setting-up-an-https-sever-with-node-amazon-ec2-nginx-and-lets-encrypt-46f869159469](https://blog.cloudboost.io/setting-up-an-https-sever-with-node-amazon-ec2-nginx-and-lets-encrypt-46f869159469)
* [https://letsencrypt.org/](https://letsencrypt.org/)
* [https://www.ssllabs.com/ssltest/](https://www.ssllabs.com/ssltest/)
* [https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/)
* [https://cryptography.io/en/latest/hazmat/primitives/padding/](https://cryptography.io/en/latest/hazmat/primitives/padding/)
* [https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/)
* [https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
* [https://docs.python.org/3/library/os.html](https://docs.python.org/3/library/os.html)
* [https://docs.python.org/3/library/json.html](https://docs.python.org/3/library/json.html)
* [http://www.pyinstaller.org/](http://www.pyinstaller.org/)
* [https://www.codementor.io/olatundegaruba/nodejs-restful-apis-in-10-minutes-q0sgsfhbd](https://www.codementor.io/olatundegaruba/nodejs-restful-apis-in-10-minutes-q0sgsfhbd)
* [https://www.youtube.com/playlist?list=PL4cUxeGkcC9jBcybHMTIia56aV21o2cZ8&fbclid=IwAR2VYRJia8zwmz7uB92T0wPn9CmwGILH5esQD2ikUaT5RIjp4qI6Kl_N2GQ](https://www.youtube.com/playlist?list=PL4cUxeGkcC9jBcybHMTIia56aV21o2cZ8&fbclid=IwAR2VYRJia8zwmz7uB92T0wPn9CmwGILH5esQD2ikUaT5RIjp4qI6Kl_N2GQ)
* [https://jwt.io/introduction/](https://jwt.io/introduction/)
* [https://scotch.io/tutorials/authenticate-a-node-js-api-with-json-web-tokens](https://scotch.io/tutorials/authenticate-a-node-js-api-with-json-web-tokens)

### **Using Windows Subsystem for Linux**

* If you don't have bash install from here: https://docs.microsoft.com/en-us/windows/wsl/install-win10
* Download and install Ubuntu for Windows 10.
* Make sure you have the .pem file in current directory.
* From bash, type in commands

_For Ransomware server:_

```
$ chown :root cecs378.pem
$ chmod 600 cecs378.pem
$ ssh -i cecs378.pem ubuntu@ec2-18-224-216-174.us-east-2.compute.amazonaws.com
```

## Mini-Cheatsheet for Git Instructions:
#### Helpful Definitions:
* **Master Branch**: branch with latest working code (main program)
* **Remote Branch**: your current local branch
* **Upstream Branch**: branch that can be tracked by GitHub
* **Origin**: perform operation on the source of your target

### Changing to a *New* Branch:
*making a new branch with all your current work*
```
git checkout -b {newbranchname}
```

### Changing to a Branch:
*this is your private workspace*
```
git checkout {branchname}
```

### Pushing to a Branch:
*whenever you push, you should ALWAYS **ADD**, **COMMIT**, then **PULL** first*
```
git add .                    // period means "everything", you can optionally chose to add only specific files
git commit -m "message"      // **REQUIRED** every commit requires a message
git pull origin master       // pulls code FROM master TO whichever branch you're on (if you are already on master branch, keyword origin is optional)
        // **ALWAYS** pull before you push (make sure to add and commit first; to avoid overriding data)
git push                     // push to your upstream branch
```
**Order of Operations:   	 Add -> Commit -> Pull -> Push**

### Pushing to Your Branch for the First Time:
*must set upstream so that github can track it* 
```
git push -u origin {branchname}    // -u argument is only necessary in your first push on a new branch
```

### View Status of Modified Files:
```
git status
```

### View Specific Changes Within Files:
```
git diff                   // overview of things changed
git diff {filename}        // see specific changes in file 
git diff {branchname}      // view differences between branches
:wq                        // exits vim mode

```

### View List of Commits:
```
git log      // view commit log
git checkout {first 6 characters of chosen checkpoint hash} -b {new branch name}  // checkout log to new branch
```
----