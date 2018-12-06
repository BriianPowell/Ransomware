## How to install Nginx, Let's Encrypt, and OpenSSL 1.3 on Ubuntu 18.04
**Created by: [Sotheanith](https://github.com/sotheanith)**

*In order to avoid any unexpected error, please perform procedures described below only one a freshly installed machine. If you know what you are doing, please disregard this warning.*

*I simply recompile all information online into a single place, so that I may be able to simplify the process.*

*For this procedure, our domain will be "example.com"*

1. "sudo apt-get update" //Fetches the list of available updates

2. "sudo apt-get upgrade" //Strictly upgrades the current packages

3. "sudo apt-get dist-upgrade" //Install updates (new ones)

4. "sudo apt-get install nginx-extras" //Install the extras version of nginx

5. "sudo nano /etc/nginx/sites-available/default/" //Edit the default configuration of the nginx

6. Under "listen [::]:80 default_server;", add "server_name example.come www.example.com". Save and exit.

7. "sudo nginx -t" //Reload nginx configuration

8. "sudo apt-get update" //Fetches the list of available updates

9. "sudo apt-get install software-properties-common" //Install property common

10. "sudo add-apt-repository ppa:certbot/certbot" //Add repo 

11. "sudo apt-get update" //Add update

12. "sudo apt-get install python-certbot-nginx" //Install certbot

13. "sudo certbot --nginx -d example.com -d www.example.com" //Start the certification process. Please follow its instruction. 

14. "sudo rm -rf /etc/nginx/sites-enabled/default" //Remove the linkage to the default configuration.

15. "sudo nano /etc/nginx/sites-available/example.com"// Create our configuration file. Please use the following example:

```
server {
listen 80;
listen [::]:80;
server_name example.com www.example.com;
return 301 https://$server_name$request_uri;
}

server {
listen 443 ssl http2 default_server;
listen [::]:443 ssl http2 default_server;
server_name example.com www.example.com;

location / {
proxy_pass http://localhost:3000;
}

ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;

ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

ssl_protocols TLSv1.2 TLSv1.3;

ssl_prefer_server_ciphers on;

ssl_ciphers 'TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:TLS-AES-128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';

ssl_session_timeout 1h;

add_header Strict-Transport-Security “max-age= 63072000” always;
}
```

16. "sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com" //Create soft link between sites-available and sites-enabled.

17. "sudo nginx -t" //Reload nginx setting.

18. "sudo mkdir /etc/systemd/system/nginx.service.d" //Create override nginx setting

19. "sudo nano /etc/systemd/system/nginx.service.d/override.conf" //Create the conf file and put this in it:

```
[Service]
ExecStartPost=/bin/sleep 0.1
```

20. "sudo systemctl daemon-reload" //reload conf

21. "sudo service nginx start" //start nginx

22. "sudo apt update" //prepare for the installation of OpenSSL 1.1.1

23. "sudo apt install build-essential checkinstall zlib1g-dev -y" //Get the chain tools

24. "cd /usr/local/src/"

25. "sudo wget https://www.openssl.org/source/openssl-1.1.1.tar.gz" //Dowload OpenSSL file.

26. "tar -xf openssl-1.1.1.tar.gz" //Extract it

27. "cd openssl-1.1.1" //go to the extracted folder.

28. "sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared" //Configure build.

29. "sudo make" //Compile

30. "sudo make install" //Install OpenSSL

31. "cd /etc/ld.so.conf.d/" //Start linking process

32. "sudo nano openssl-1.1.1.conf" //Create configure file and add this into it "/usr/local/ssl/lib".

33. "sudo ldconfig -v" //reload the config

34. "sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.BEKUP" //Backup pre-existing files

35. "sudo mv /usr/bin/openssl /usr/bin/openssl.BEKUP"

36. "sudo nano /etc/environment" //Edit enviroment file and add ":/usr/local/ssl/bin" before the ending quotation.

37. "source /etc/environment" //reload the enviroment

38. "echo $PATH" //Show path

39. "openssl version -a" // Check openssl version. It should show OpenSSL 1.1.1

40. "sudo nginx -V" //Make sure it said running with OpenSSL 1.1.1 on the "built with."

41. "sudo service nginx restart" //restart the nginx

**Congratulations. You have set up Nginx to work with OpenSSL 1.1.1 on Ubuntu 18.04**

*Resources*:

* https://www.howtoforge.com/tutorial/how-to-install-openssl-from-source-on-linux/
* https://bugs.launchpad.net/ubuntu/+source/nginx/+bug/1581864
* https://blog.cloudboost.io/setting-up-an-https-sever-with-node-amazon-ec2-nginx-and-lets-encrypt-46f869159469
* https://certbot.eff.org/lets-encrypt/ubuntubionic-nginx
