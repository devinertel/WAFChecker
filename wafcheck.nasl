# Dumping old code
# Circa 2008 WAF Checker NASL Script.
# http://www.infointox.net/?paged=7

#Create tcp socket to webserver port
socket_timeout = 5;
soc = open_sock_tcp(80);
 
#grab host ip of current box with socket open
hostip=get_host_ip();
 
#if socket was created
if (soc) {
 
#create string and send
str = string("GET /index.html HTTP/1.0\r\nUser-Agent:Nikto\r\n\r\n");
send(socket:soc, data:str);
 
#grab data from the socket
page = recv(socket:soc, length:4096);
 
#grep for the line with error or whatever waf refturns
error = egrep(pattern:"error*", string : page);
 
#if grep returns value
if(error){
display("WAF ON ",hostip,"\n");
}
else{
display("WAF OFF ",hostip,"\n");
}
 
#close socket
close(soc);
}
