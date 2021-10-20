const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
let crypto = require("crypto");

const port = 3000;


const config = {
	dbUrl: 'mongodb://localhost:27017/uls',
	accessToken: 'ac24234ac38bdf3ab8ab561a',
	slatRound: 10
};

mongoose.connect(config.dbUrl);
let db = mongoose.connection;
db.once('open', function () {
	console.log('connected to mongoDB');
})
db.on('error', function (err) {
	console.log(err);
})

const UserSchema = new mongoose.Schema({
	name: { type: String, required: true },
	email: { type: String, required: true, unique: true },
	passwordHash: { type: String, required: true },
	secret: { type: String, required: true }
})

const User = mongoose.model('user', UserSchema);


const app = express();

app.use(express.json());

function checkField(obj) {
	let errors = [];
	for (let field in obj) {
		if (obj[field] === '' || obj[field] === undefined)
			errors.push({ msg: `${field} is missing!` });
	}
	return errors;
}

function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}
app.post('/api/register', async (req, res) => {
	const { name, email, password, passwordConfirm } = req.body;
	let errors = checkField({ name, email, password, passwordConfirm });
	if (errors.length > 0) {
		res.status(400).json({
			msg: 'unable to register',
			errors
		});
	}else if (!validateEmail(email)) {
		res.status(400).json({
			msg: 'unable to register',
			errors : [{msg : 'invalid email'}]
		});
	}
	 else if (password !== passwordConfirm) {
		res.status(400).json({
			msg: 'unable to register',
			errors: { msg: 'password does not match with confirm password' }
		});
	} else {
		try {

			let salt = bcrypt.genSaltSync(config.slatRound);
			let passwordHash = bcrypt.hashSync(password, salt);
			let user = new User({
				name,
				email,
				passwordHash,
				secret: "happylogin"
			});
			let u = await user.save();
			console.log(u);
			res.status(200).json({
				msg: 'registration Successful! you can login now!',
			});
		} catch (errors) {
			console.log(errors);
			res.status(400).json({
				msg: 'unable to register!',
				errors
			});
		}
	}
});

app.post('/api/login', async (req, res) => {
	let { email, password } = req.body;
	let errors = checkField({ email, password });
	if (errors.length > 0) {
		res.status(400).json({
			msg: 'unable to login',
			errors
		});
	} else {
		try {
			let user = await User.findOne({ email });
			if (user) {

				let stat = bcrypt.compareSync(password, user.passwordHash);
				if (!stat) {
					res.status(400).json({
						msg: 'unable to login!',
						errors: [{ msg: 'wrong password' }]
					});
				} else {
					let userData = { id: String(user._id), secret: user.secret };
					console.log(userData);
					const accessToken = jwt.sign(userData, config.accessToken);


					res.status(200).json({
						msg: 'login successful',
						accessToken
					})
				}
			}else {
				res.status(400).json({
					msg: 'email not registeered!',
					errors
				});	
			}
		} catch (err) {
			console.log(err);
			res.status(400).json({
				msg: 'unable to register!',
				err
			});
		}
	}
});

function Authenticate(req, res, next) {
	const hAuthToken = req.headers['auth'];
	if (!hAuthToken) res.status(400).json({ error: "header auth missing" });
	jwt.verify(hAuthToken, config.accessToken, (err, userData) => {
		if (err) res.status(403).json({ error: "auth token is not valid" });
		console.log(userData);
		User.findById(userData.id, (err, user) => {
			if (err) res.status(403).json({ error: "auth token is not valid" });
			if(user.secret != userData.secret) res.status(403).json({ error: "auth token is not valid" });
			req.user = user;
			next();
		});
	});
}

app.get('/api/dashboard', Authenticate, (req, res) => {
	res.status(200).json(req.user);
});
app.get('/api/logout', Authenticate,async (req, res) => {
	try {
		await User.findByIdAndUpdate(req.user._id, {
			secret: crypto.randomBytes(32).toString('hex')
		})
		res.status(200).json({msg: 'Logged out Successfully!!'});
	}catch(e) {
		if (e) res.status(403).json({ error: "auth token is not valid" });
	}
})

app.use(express.static(__dirname + '/public'));




app.listen(port, () => {
	console.log(`listeneing on port ${port}`);
})