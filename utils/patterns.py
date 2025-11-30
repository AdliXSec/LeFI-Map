NEGATIVE_PATTERNS = [
    "failed to open stream",
    "Failed opening required",
    "open_basedir restriction in effect",
    "File does not exist:",
    "function.main",
    "function.include",
    "Warning: include",
    "No such file or directory"
]

POSITIVE_PATTERNS = [
    "root:x:0:0",
    "daemon:x:1:1",
    "sbin/nologin",
    "users:x",
    "[boot loader]",
    "owner=",
    "[drivers]",
    "DB_NAME",
    "database_prefix=",
    "adminuser=",
    "DOCUMENT_ROOT=",
    "HTTP_USER_AGENT=",
    "State: R (running)",
    "GET / HTTP/1.1",
    "apache_port=",
    "[error] [client"
]
    
HARD_POSITIVE_PATTERNS = [
    "root:x:0:0",                  
    "daemon:x:1:1",                 
    "root:$",                      
    "sbin/nologin",                 
    "users:x:",                    
    "Linux version",               
    "Ubuntu", "Debian", "CentOS",  
    "127.0.0.1 localhost",         
    "-----BEGIN RSA PRIVATE KEY-----", 
    "ssh-rsa",                     

    "[boot loader]",               
    "[fonts]", "[extensions]",     
    "MCI Extensions",              
    "owner=", "[drivers]",         
    "# Software: Microsoft Internet Information Services", 
    "C:\\Windows\\System32\\drivers\\etc\\hosts", 

    "DB_NAME", "DB_USER", "DB_PASSWORD", 
    "AUTH_KEY", "SECURE_AUTH_KEY",      
    "public $user", "public $password", "public $db",
    "'database' =>", "'username' =>",  
    "APP_KEY=", "DB_HOST=", "MAIL_USERNAME=", 
    "SECRET_KEY =", "SQLALCHEMY_DATABASE_URI",
    "session.save_path",               
    "mysql:host=", "mysqli_connect",   

    "DOCUMENT_ROOT=", "SERVER_NAME=",  
    "HTTP_USER_AGENT=", "REMOTE_ADDR=",
    "State: R (running)", "Tgid:",     
    "TracerPid:", "Uid:",              

    "] \"GET / HTTP/1.1\"",            
    "] \"POST / HTTP/1.1\"",           
    "[error] [client",                
    "sshd[", "Accepted password for", 
    "client denied by server configuration", 
        
    "<?php", "$_GET[", "include(",     
    "def ", "import ", "class ",      
    "function(", "require(", "const ",
    "public class", "import java.io"  
]