# Ransomware
Ransomware created for CECS 378 at CSULB

Located at: www.onestyle.tech

### Using Windows Subsystem for Linux

* If you don't have bash install from here: https://docs.microsoft.com/en-us/windows/wsl/install-win10
* Download and install Ubuntu for Windows 10.
* Make sure you have the file looforyou.pem in current directory.
* From bash, type in commands

_For Ransomware server:_

```
$ chown :root cecs378.pem
$ chmod 600 cecs378.pem
$ ssh -i .pem ubuntu@ec2-18-221-179-247.us-east-2.compute.amazonaws.com
```

## Git Instructions: mini cheatsheet of the most important git code
----
#### Terms
* **master branch** - branch with latest working code (main program)
* **remote branch** - your own branch
* **upstream branch** - branch that can be tracked
* **origin** - perform operation on the source of your target


### going to a branch:
* this is your private workspace
```
git checkout {branchname}
```

### going to a *new* branch
* making a new branch with all the work you have
```
git checkout -b {newbranchname}
```

### when pushing to your branch for the first time
* must set upstream so that github can track it 
```
git push -u origin {branchname}    //you only need the -u argument in your very first push. 
```

### pushing to a branch
* whenever you push, you should ALWAYS **ADD**, **COMMIT**, then **PULL** first
```
git add .                    //period means "everything". you can also choose to add only specific files
git commit -m "message"      //**REQUIRED** you need to type in a message for every commit
git pull origin master       //this pulls code FROM master TO whatever branch you're on (if you are already on master branch, keyword origin is optional)
//ALWAYS pull before you push (make sure to add and commit first) to avoid overriding data
git push                     //push to your branch
```
* order of operations:   	 add -> commit -> pull -> push

### see status of files modified
```
git status
```

### see specific changes within files:
```
git diff                   // overview of things changed
git diff {filename}        // see specific changes in file 
git diff {branchname}      // view differences in different branches
:wq                        // exits vim mode

```

### see list of commits
```
git log      // view commit log
git checkout {first 6 characters of chosen checkpoint hash} -b {new branch name}  // checkout log to new branch
```
----
