var http = require('http');
var url = require('url');
var net = require('net');
var socks5 = require('simple-socks');
var fmt = require('util').format;
var dns = require('dns');
var yargs = require('yargs');

var args = yargs
	.usage('Usage: $0 -u <username> -p <password>')
	.demand(['u', 'p'])
	.argv;

//httpProxy();
socksServer();

function httpProxy() {
	var conId = 0;

	var server = http.createServer(function(req, res) {
		log('HTTP ' + req.connection.remoteAddress + ' ' + req.method + ' ' + req.url);
		res.end();
	});

	server.on('connect', function(req, sourceSocket, head) {
		if (req.headers['proxy-authorization'] !== 'Basic TODO') { // TODO: Convert user/pass
			log('Unauthenticated request from ' + req.connection.remoteAddress);
			sourceSocket.write(
				'HTTP/1.0 407 Proxy Authentication Required\r\n' +
				'Proxy-Authenticate: Basic realm="NRMXLR"\r\n' +
				'\r\n'
			);
			sourceSocket.end();
			return;
		}

		var id = ++conId;
		log('HTTP #' + id + ' CON ' + req.url);
		var dest = url.parse('http://' + req.url);
		var destSocket = net.connect(dest.port, dest.hostname, function() {
			log('HTTP #' + id + ' TUN ' + req.url);
			sourceSocket.write(
				'HTTP/1.1 200 Connection Established\r\n' +
				'Proxy-agent: httptun\r\n' +
				'\r\n'
			);
			destSocket.write(head);
			destSocket.pipe(sourceSocket);
			sourceSocket.pipe(destSocket);
		});

		destSocket.on('error', function() {
			log('HTTP #' + id + ' ERR');
		});

		destSocket.on('close', function() {
			log('HTTP #' + id + ' END', req.url);
		});
	});

	server.listen(4455, function() {
		log('HTTP proxy listening on port 4455...');
	});
}

function socksServer() {
	var dnsCache = {};

	var server = socks5.createServer({
		authenticate: function(username, password, callback) {
			if (username === args.u && password === args.p) {
				return setImmediate(callback);
			}

			return setImmediate(callback, new Error('incorrect username and password'));
		}
	});

	server.listen(4466);
	log('SOCKS5 listening on port 4466...');

	// When authentication succeeds
	/*server.on('authenticate', function (username) {
	 log('SOCKS5 auth success for %s', username);
	 });*/

	// When authentication fails
	server.on('authenticateError', function(username, err) {
		log('SOCKS5 auth fail for %s: %s', username, err.message);
	});

	// When a reqest arrives for a remote destination
	server.on('proxyConnect', function(info, destination) {
		var domain = dnsCache[info.host] && dnsCache[info.host].domain;
		log('SOCKS5 proxy conn to %s:%d%s', info.host, info.port, domain ? ' (' + domain + ')' : '');
		if (!domain) reverseLookup(info.host);
	});

	// When an error occurs connecting to remote destination
	server.on('proxyError', function(err) {
		logerr('SOCKS5 proxy err: %s', err.message);
	});

	// When a proxy connection ends
	server.on('proxyEnd', function(response, args) {
		log('SOCKS5 proxy end: %s', response);
	});

	function reverseLookup(host) {
		if (typeof host !== 'string')
			return;

		if (dnsCache[host] && dnsCache[host].timeout != null)
			return;

		if (!dnsCache[host]) {
			// Abort if not a valid IP.
			if (!host.match(/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/))
				return;

			dnsCache[host] = {
				attempts: 0
			};
		}

		// Abort if found domain, has in-progress reverse lookup, or attempted too many times.
		if (dnsCache[host].domain || dnsCache[host].attempts >= 10)
			return;

		dnsCache[host].attempts++;

		var timeoutId = dnsCache[host].timeout = setTimeout(function() {
			delete dnsCache[host].timeout;
			logerr('SOCKS4 reverse DNS timeout for %s (attempt %s)', host, dnsCache[host].attempts);
		}, 5000);

		dns.reverse(host, function(err, domains) {
			if (dnsCache[host].timeout === timeoutId) {
				clearTimeout(dnsCache[host].timeout);
				delete dnsCache[host].timeout;

				if (err) {
					logerr('SOCKS4 reverse DNS error for %s: %s (attempt %s)', host, err.message, dnsCache[host].attempts);
				}
				else if (!domains.length) {
					logerr('SOCKS4 reverse DNS no domains for %s (attempt %s)', host, dnsCache[host].attempts);
				}
				else {
					dnsCache[host].domain = domains[0];
					log('SOCKS5 reverse DNS %s -> %s', host, domains.join(''));
				}
			}
		});
	}
}

function log() {
	return console.log('[' + new Date().toUTCString() + '] ' + fmt.apply(null, arguments));
}

function logerr() {
	return console.error('[' + new Date().toUTCString() + '] ' + fmt.apply(null, arguments));
}
