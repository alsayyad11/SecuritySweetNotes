Google Dorks for Bug Bounty | Find Sensitive Information 

1. Discovering Exposed Files:
- intitle:"index of" "site:http://site.com"
- filetype:log inurl:log site:http://site.com
- filetype:sql inurl:sql site:http://site.com
- filetype:env inurl:.env site:http://site.com

2. Finding Sensitive Directories:
- inurl:/phpinfo.php site:http://site.com
- inurl:/admin site:http://site.com
- inurl:/backup site:http://site.com
- inurl:wp- site:http://site.com

3. Exposed Configuration Files:
- filetype:config inurl:config site:http://site.com
- filetype:ini inurl:wp-config.php site:http://site.com
- filetype:json inurl:credentials site:http://site.com

4. Discovering Usernames and Passwords:
- intext:"password" filetype:log site:http://site.com
- intext:"username" filetype:log site:http://site.com
- filetype:sql "password" site:http://site.com

5. Finding Database Files:
- filetype:sql inurl:db site:http://site.com
- filetype:sql inurl:dump site:http://site.com
- filetype:bak inurl:db site:http://site.com

6. Exposed Git Repositories:
- inurl:".git" site:http://site.com
- inurl:"/.git/config" site:http://site.com
- intitle:"index of" ".git" site:http://site.com

7. Finding Publicly Exposed Emails:
- intext:"email" site:http://site.com
- inurl:"contact" intext:"
@site
.com" -www.site.com
- filetype:xls inurl:"email" site:http://site.com

8. Discovering Vulnerable Web Servers:
- intitle:"Apache2 Ubuntu Default Page: It works" site:http://site.com
- intitle:"Index of /" "Apache Server" site:http://site.com
- intitle:"Welcome to nginx" site:http://site.com

9. Finding API Keys:
- filetype:env "DB_PASSWORD" site:http://site.com
- intext:"api_key" filetype:env site:http://site.com
- intext:"AWS_ACCESS_KEY_ID" filetype:env site:http://site.com

10. Exposed Backup Files:
- filetype:bak inurl:backup site:http://site.com
- filetype:bak inurl:backup site:http://site.com
- filetype:zip inurl:backup site:http://site.com
- filetype:tgz inurl:backup site:http://site.com
