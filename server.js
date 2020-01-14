process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; //NOT RECOMMENDED, remove once deployed on a HTTPS server
var fs = require('fs');
var url = require('url');
var http = require('http');
// var https = require('https');
var flash = require('connect-flash');
var morgan = require('morgan');
var express = require('express');
var session = require('express-session');
var passport = require('passport');
var mongoose = require('mongoose');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var BasicStrategy = require('passport-http').BasicStrategy;
var LocalStrategy = require('passport-local').Strategy;
var PassportOAuthBearer = require('passport-http-bearer');
var morgan = require('morgan');
var cookieSession = require('cookie-session');
const request = require('request');
var oauthServer = require('./oauth');
const account = require('./models/account');
const fetch = require('node-fetch');


var port = (process.env.VCAP_APP_PORT || process.env.PORT || 3000);
var host = (process.env.VCAP_APP_HOST || '0.0.0.0');
var mongo_url = process.env.MONGO_URL || 'mongodb://localhost/users';

console.log(mongo_url);
mongoose.Promise = global.Promise;
var mongoose_options = {
	server: {
		auto_reconnect: true,
		autoReconnect: true,
		reconnectTries: Number.MAX_VALUE,
		reconnectInterval: 1000,
		socketOptions: {
			autoReconnect: true
		}
	}
};
var mongoose_connection = mongoose.connection;

mongoose_connection.on('connecting', function () {
	console.log('connecting to MongoDB...');
});

mongoose_connection.on('error', function (error) {
	console.error('Error in MongoDb connection: ' + error);
	//mongoose.disconnect();
});

mongoose_connection.on('connected', function () {
	console.log('MongoDB connected!');
});

mongoose_connection.once('open', function () {
	console.log('MongoDB connection opened!');
});

mongoose_connection.on('reconnected', function () {
	console.log('MongoDB reconnected!');
});

mongoose_connection.on('disconnected', function () {
	console.log('MongoDB disconnected!');
});

mongoose.connect(mongo_url, mongoose_options);

var Account = require('./models/account');
var oauthModels = require('./models/oauth');



var app_id = 'https://alexa-oauth.herokuapp.com:' + port;
var cookieSecret = 'ihytsrf334';

var app = express();

app.set('view engine', 'ejs');
app.enable('trust proxy');
app.use(morgan("combined"));
// app.use(cookieParser(cookieSecret));
app.use(cookieSession({
	keys: ['secret1', 'secret2']
}));
app.use(flash());
/* app.use(session({
  // genid: function(req) {
  //   return genuuid() // use UUIDs for session IDs
  // },
  secret: cookieSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
  	secure: true
  }
})); */
app.use(bodyParser.json());
app.use(express.urlencoded());
app.use(passport.initialize());
app.use(passport.session());

function requireHTTPS(req, res, next) {
	if (req.get('X-Forwarded-Proto') === 'http') {
		//FYI this should work for local development as well
		var url = 'http://' + req.get('host');
		if (req.get('host') === 'localhost') {
			url += ':' + port;
		}
		url += req.url;
		return res.redirect(url);
	}
	next();
}

app.use(requireHTTPS);

app.use('/', express.static('static'));

passport.use(new LocalStrategy(Account.authenticate()));

passport.use(new BasicStrategy(Account.authenticate()));

passport.serializeUser(Account.serializeUser());
passport.deserializeUser(Account.deserializeUser());

var accessTokenStrategy = new PassportOAuthBearer(function (token, done) {
	console.log("accessTokenStrategy: %s", token);
	oauthModels.AccessToken.findOne({ token: token }).populate('user').populate('grant').exec(function (error, token) {
		/* 		console.log("db token: %j", token);
					console.log("db token.active: " + token.active);
					console.log("db token.grant : " + token.grant.active);
					console.log("db token.user: " + token.user); */
		if (token && token.active && token.grant.active && token.user) {
			// console.log("Token is GOOD!");
			console.log("db token: %j", token);
			console.log("db token.active: " + token.active);
			console.log("db token.grant : " + token.grant.active);
			console.log("db token.user: " + token.user);
			done(null, token.user, { scope: token.scope });
		} else if (!error) {
			console.log("TOKEN PROBLEM");
			done(null, false);
		} else {
			console.log("TOKEN PROBLEM 2");
			console.log(error);
			done(error);
		}
	});
});

passport.use(accessTokenStrategy);

function ensureAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	} else {
		res.redirect('/login');
	}
}

app.get('/', function (req, res) {
	res.render('pages/index', { user: req.user, home: true });
});

app.get('/login', function (req, res) {
	res.render('pages/login', { user: req.user, message: req.flash('error') });
});

app.get('/logout', function (req, res) {
	req.logout();
	if (req.query.next) {
		res.redirect(req.query.next);
	} else {
		res.redirect('/');
	}
});

//app.post('/login',passport.authenticate('local', { failureRedirect: '/login', successRedirect: '/2faCheck', failureFlash: true }));
app.post('/login',
	passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),
	function (req, res) {
		if (req.query.next) {
			res.redirect(req.query.next);
		} else {
			res.send(`https://alexa-oauth.herokuapp.com/auth/start`);
		}
	});

app.get('/newuser', function (req, res) {
	res.render('pages/register', { user: req.user, })
});

app.post('/newuser', function (req, res) {
	Account.register(
		new Account({ username: req.body.username, email: req.body.email, mqttPass: "foo" }),
		req.body.password, function (err, account) {
			if (err) {
				console.log(err);
				return res.status(400).send(err.message);
			}

			passport.authenticate('local')(req, res, function () {
				console.log("created new user %s", req.body.username);
				res.status(201).send();
			});

		});
});

let phoneNo, responseS, resOtp, resKey, sentOpt, resData, custId, custName, custEmail, optStat, submittedMpin;
app.post('/honda/primary', (req, res) => {
	// console.log(req)
	var clientId = req.body.clientId;
	var scope = req.body.scope;
	var responseType = req.body.responseType;
	var redirectURI = req.body.redirectURI;
	var state = req.body.state
	phoneNo = req.body.primaryMobileNo;
	console.log([clientId, scope, responseType, redirectURI, state]);
	var options = {
		'method': 'POST',
		'url': 'https://169.38.98.215:7143/bos/customer/verifyPrimaryContactNo',
		'headers': {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ "primaryMobileNo": phoneNo, "emailId": "" })

	};
	request(options, function (error, response) {
		if (error) throw new Error(error);
		responseS = JSON.parse(response.body);
		// let num = req.body.primaryMobileNo;
		resOtp = responseS.data.generatedOtp;
		console.log(resOtp);
		resKey = responseS.data.key;
		if (responseS.data.mpinStatus == false) {
			// setTimeout(res, 2000);	
			return res.status(403).render('honda', { fail: true, otpSent: false, number: phoneNo, otpVerified: undefined });
		}
		res.render('honda', { fail: false, otpSent: true, number: phoneNo, otpVerified: undefined });
		app.post('/honda/verifyOtp', (req, res) => {
			sentOpt = req.body.otp;
			var options = {
				'method': 'POST',
				'url': 'https://169.38.98.215:7143/bos/authentication/verifyOtpPin',
				'headers': {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({ key: resKey, otp: sentOpt, emailId: "", primaryMobileNo: phoneNo, customerId: "", customerCategory: "" })

			};
			// console.log(options)
			request(options, async function (error, response) {
				if (error) throw new Error(error);
				resData = JSON.parse(response.body);
				custId = resData.data.loginInfo.customerId;
				custName = resData.data.loginInfo.firstname;
				custEmail = resData.data.loginInfo.emailId;
				optStat = resData.data.otpStatus;
				if (optStat == 'False') { return res.render('honda', { fail: false, otpSent: true, number: phoneNo, otpVerified: false }) }
				let checkUser = await account.findOne({ email: custEmail })
				if (!checkUser) {
					var options = {
						'method': 'POST',
						'url': `https://alexa-oauth.herokuapp.com/newuser`,
						'headers': {
							'Content-Type': 'application/x-www-form-urlencoded'
						},
						form: {
							'username': custName,
							'email': custEmail,
							'password': custId
						}
					}
					request(options, function (error, response) {
						if (error) throw new Error(error);
						console.log(response.body);
					});
				}

				res.render('honda', { fail: undefined, otpSent: undefined, number: phoneNo, otpVerified: true, mpinVerified: undefined });

				app.post('/honda/verifyMpin', (req, res) => {
					submittedMpin = req.body.mpin;
					var options = {
						'method': 'POST',
						'url': 'https://169.38.98.215:7143/bos/authentication/loginApi',
						'headers': {
							'Content-Type': 'application/json',
							'mpin': submittedMpin,
							'customerId': custId,
							'customerCategory': 'Primary'
						},
						body: JSON.stringify({ emailId: "", primaryMobileNo: phoneNo })
					};
					request(options, async function (error, response) {
						console.log(response.headers);
						if (error) throw new Error(error);
						responseS = JSON.parse(response.body);
						if (responseS.status.status == true) {
							
							let checkIfData = await account.findOne({ email: custEmail })
							console.log("value of checkIfData" + checkIfData) 
							if (!checkIfData.data) {

								await account.findOneAndUpdate({ email: custEmail }, { $set: { data: responseS.data, status: responseS.status, accessToken: response.headers.refreshtoken, refreshToken: response.headers.accesstoken } })
							}
							
/* 							var urlencoded = new URLSearchParams();
							urlencoded.append("username", custName);
							urlencoded.append("password", custId);
							
							var requestOptions = {
							  method: 'POST',
							  headers: {"Content-Type": "application/x-www-form-urlencoded"},
							  body: urlencoded,
							  redirect: 'follow'
							};
							
							fetch("http://localhost:3000/login", requestOptions)
							  .then(response => response.text())
							  .then(result => res.send(result))
							  .catch(error => console.log('error', error)); */

							var options = {
								'method': 'POST',
								'url': `https://alexa-oauth.herokuapp.com/login`,
								'headers': {
									'Content-Type': 'application/x-www-form-urlencoded'
								},
								form: {
									'username': custName,
									'password': custId
								}
							}
							request(options, function (error, response, body) {
								if (error) throw new Error(error);
								// console.log(response.body);
								// res.redirect(`/auth/start?client_id=${clientId}&response_type=${responseType}&redirect_uri=${redirectURI}&scope=${scope}`);
								// res.send(body);
								console.log("value of login response after post" + JSON.stringify(body));
							
							
							
							
								res.redirect(`${response.body}?scope=${scope}&client_id=${clientId}&redirect_uri=${redirectURI}&response_type=${responseType}&CustName=${custName}&CustId=${custId}&State=${state} `)	
								
								
							});
						}
						else {
							res.render('honda', { fail: undefined, otpSent: undefined, number: phoneNo, otpVerified: true, mpinVerified: false });
						}
					})
				})
			});
		});
	});
});


app.get('/honda/primary', (req, res) => {
	//console.log("honda primary get request" + JSON.stringify( req));
	res.render('honda', { fail: false, otpSent: false, otpVerified: undefined, clientId:req.query.client_id, responseType: req.query.response_type, redirectURI: req.query.redirect_uri, scope: req.query.scope, State : req.query.state });
});

app.get('/auth/start', oauthServer.authorize(function (applicationID, redirectURI, done) {
	oauthModels.Application.findOne({ oauth_id: applicationID }, async function (error, application) {
		if (application) {
			var match = false, uri = url.parse(redirectURI || '');
			for (var i = 0; i < application.domains.length; i++) {
				console.log("%s - %s - %j", application.domains[i], redirectURI, uri);
				if (uri.host == application.domains[i] || (uri.protocol == application.domains[i])) {
					match = true;
					break;
				}
			}
			if (match && redirectURI && redirectURI.length > 0) {
				let user  = await account.findOne({ email: custEmail })
				done(null, application, redirectURI);
			} else {
				done(new Error("You must supply a redirect_uri that is a domain or url scheme owned by your app."), false);
			}
		} else if (!error) {
			done(new Error("There is no app with the client_id you supplied. " + applicationID), false);
		} else {
			done(error);
		}
	});
}), function (req, res) {

	//console.log("value of req in request iside auth start" + (req.oauth2.req))
	console.log("value of CustName in request iside auth start" + req.query.CustName)
	
	console.log("value of CustId in request iside auth start" + req.query.CustId)
	var scopeMap = {
		// ... display strings for all scope variables ...
		access_devices: 'ACCESS USER PROFILE DETAILS',
		create_devices: 'create new devices.'
	};

	res.render('pages/oauth', {
		transaction_id: req.oauth2.transactionID,
		currentURL: encodeURIComponent(req.originalUrl),
		response_type: req.query.response_type,
		errors: req.flash('error'),
		scope: req.oauth2.req.scope,
		application: req.oauth2.client,
		customerId : req.query.CustId,
		customerName : req.query.CustName,
		user: req.user,
		map: scopeMap,
		state :req.query.State
	});
});

app.post('/auth/finish', function (req, res, next) {
	console.log("/auth/finish inside");
	if (req.user) {
		next();
	} else {
		passport.authenticate('local', {
			session: false
		}, function (error, user, info) {
			console.log("/auth/finish authenting");
			if (user) {
				console.log(user.username);
				req.user = user;
				next();
			} else if (!error) {
				console.log("not authed"+info);
				req.flash('error', 'Your email or password was incorrect. Please try again.');
				res.redirect(req.body['auth_url'])
			}
		})(req, res, next);
	}
}, oauthServer.decision(function (req, done) {
	console.log("decision user: ", req);
	done(null, { scope: req.oauth2.req.scope, state = req.query.state });
}));


app.post('/auth/exchange', function (req, res, next) {
	var appID = req.body['client_id'];
	var appSecret = req.body['client_secret'];

	console.log(req.body);
	console.log(req.headers);
	console.log("Looking for ouath_id = %s", appID);

	oauthModels.Application.findOne({ oauth_id: appID, oauth_secret: appSecret }, function (error, application) {
		if (application) {
			console.log("found application - %s", application.title);
			req.appl = application;
			next();
		} else if (!error) {
			console.log("no matching application found");
			error = new Error("There was no application with the Application ID and Secret you provided.");
			next(error);
		} else {
			console.log("some other error, %j", error);
			next(error);
		}
	});
}, oauthServer.token(), oauthServer.errorHandler());

app.post('/command',
	passport.authenticate('bearer', { session: false }),
	function (req, res, next) {
		console.log('Entered');
		console.log(req.user.username);
		console.log(req.body);
		res.send({ userData: req.user });
	}
);

app.put('/services',
	function (req, res, next) {
		console.log("hmm put");
		next();
	},
	passport.authenticate('basic', { session: false }),
	function (req, res) {
		console.log("1");
		if (req.user.username == 'admin') {
			console.log("2");
			console.log(req.body);
			var application = oauthModels.Application(req.body);
			application.save(function (err, application) {
				if (!err) {
					res.status(201).send(application);
				} else {
					res.status(500).send();
				}
			});
		} else {
			res.status(401).send();
		}
	});

app.get('/services',
	function (req, res, next) {
		console.log("hmm");
		next();
	},
	passport.authenticate('basic', { session: false }),
	function (req, res) {
		if (req.user.username == 'admin') {
			oauthModels.Application.find({}, function (error, data) {
				res.send(data);
			});
		}
	}
);

app.options('/testing',
	function (req, res, next) {
		res.set("Access-Control-Allow-Origin", "*");
		res.set("Access-Control-Allow-Methods", "GET,OPTIONS");
		res.set("Access-Control-Allow-Credentials", "true");
		res.set("Access-Control-Allow-Headers", "Authorization");
		res.status(200).end();
	}
);

app.get('/testing',
	function (req, res, next) {
		res.set("Access-Control-Allow-Origin", "*");
		next();
	},
	passport.authenticate('bearer', { session: false }),
	function (req, res, next) {
		res.set("Access-Control-Allow-Origin", "*");
		res.send({ 'test': 'sucess' });
	}
);

app.get('/test', (req, res) => {
	var val = req.query.value;
	console.log(val);
	res.end();
})

var server = http.Server(app);
if (app_id.match(/^http:\/\/localhost:/)) {
	var options = {
		key: fs.readFileSync('server.key'),
		cert: fs.readFileSync('server.crt')
	};
	server = http.createServer(options, app);
}


server.listen(port, host, function () {
	console.log('App listening on  %s:%d!', host, port);
	console.log("App_ID -> %s", app_id);

	setTimeout(function () {

	}, 5000);
});