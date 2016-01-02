var http = require('http'),
    fs = require('fs'),
    path = require('path'),
    url = require('url'),
    auth = require('basic-auth'),
    time = require('time'),
    child_process = require('child_process');
var lastAccessed = Date.now() / 1000 - 60 * 5;
var username, password;
fs.readFile("pw.ini", 'utf8', function (err,data) {
    if (err) {
        return console.log(err);
    }
    username = data.split(" ")[0].trim();
    password = data.split(" ")[1].trim();
});

http.createServer(function(request, response) {
    console.log("Received a request");

    var credentials = auth(request);
    if (!credentials || credentials.name !== username || credentials.pass !== password){
        response.statusCode = 401;
        response.setHeader('WWW-Authenticate', 'Basic realm="example"');
        response.end('Access denied');
        return;
    }
    
    var url_parts = url.parse(request.url, true);
    var query = url_parts.query;
    console.log(query); //{Object}
    // If get has a var in it
    if (query["download"] == "true") {
        var filePath = path.join(__dirname, 'payload.txt');
        var stat = fs.statSync(filePath);

        response.writeHead(200, {
            'Content-Type': 'text/plain',
            'Content-Length': stat.size
        });
        fs.readFile(filePath, 'utf8', function (err,data) {
            if (err) {
                return console.log(err);
            }
            response.write(data);
            console.log("Wrote file");
        });
        console.log("Writing file");
    }
    else {
        response.writeHead(200, {
            'Content-Type': 'text/plain'
        });
        var now = Date.now() / 1000;
        response.write("Executing server script; please check back in five minutes. \n\nDo not refresh this page.\n\nTo receive the file, append this to the URL: /?download=true\n\nSo if the url was joeburger.ax.lt:3001, it would become:\n\njoeburger.ax.lt:3001/?download=true\n\nWhen you check back, make sure it's at the download=true url");
            response.write("\n\nIt has been " + Math.floor(now - lastAccessed) + " seconds since the script was last run.");
        console.log(now);
        if (now - lastAccessed > 60 * 5) {
            response.write("\n\n!!! THE SCRIPT IS RUNNING !!!\n\n");
            response.end();
            lastAccessed = Date.now() / 1000;
            console.log("Executing Perl Script");
            child_process.exec("rm " + __dirname + "/lastaccessed.txt; /usr/bin/perl getVulns.pl");
            console.log("Finished Executing Perl Script");
        }
        else { 
            response.write("\n\nWait " + Math.floor(60 * 5 - (now - lastAccessed)) + " more seconds.");
            response.end();
        }
    }
})
.listen(3001);
