// Initiate the server
require('./utils.js');
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const saltRounds = 10;


const app = express();
//ENV.port || 3000 is this correct?
const PORT = process.env.PORT || 3000; // Replace with the desired port number
const node_session_secret = process.env.NODE_SESSION_SECRET;

const expireTime = 60 * 60 * 1000;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;




var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');


var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
		secret: mongodb_session_secret
	}
})

app.set('views', './views');

app.set('view engine', 'ejs')

app.use(express.static('public'));

app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
        secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true,
        cookie: {
            maxAge: expireTime
        }   
    }
));

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.redirect("/members");
        return;
    }
    res.send('<a href="/signup"><button>Sign Up</button></a><a href="/login"><button>Log In</button></a>');
})

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html');

})


app.post('/submitSignup', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username) {
        res.send('<h1>Missing name</h1> <a href="/signup"><button>Back</button></a>');
        return;
    } else if (!email) {
        res.send('<h1>Missing email</h1><a href="/signup"><button>Back</button></a>');
        return;
    }
    else if (!password) {
        res.send('<h1>Missing password</h1><a href="/signup"><button>Back</button></a>');
        return;
    }
    
    const schema = Joi.object({
            
            username: Joi.string().min(3).max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().min(3).max(20).required()
        
        });
    
    const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

   var hashedPassword = await bcrypt.hash(password, saltRounds);
   await userCollection.insertOne({username: username, email: email, password: hashedPassword, admin: false});
   console.log("Inserted user");
    res.redirect("/login");


})

app.post('/makeAdmin', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        res.send('<h1>Missing email</h1><a href="/admin"><button>Back</button></a>');
        return;
    }
    const user = await userCollection.findOne({ email: email });
    if (!user) {
        console.log("user not found");
    }
    const updatedAdminStatus = !user.admin;
    await userCollection.updateOne({ email: email }, { $set: { admin: updatedAdminStatus } });
    res.redirect("/admin");

});

app.post('/submitLogin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(30).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

    const result = await userCollection.find({email: email}).project({username: 1, password: 1, _id: 1}).toArray();
    if (result.length != 1) {
		console.log("user not found");
		res.send('<h1>User Not Found</h1> <a href="/login"><button>Back</button></a>');
		return;

	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name  = result[0].username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.send('<h1>Incorrect password</h1> <a href="/login"><button>Back</button></a>');
		return;
	}
})

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/login.html');
    res.render('login', {pageTitle: 'login'})
})


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/");
        return;
    }

    var randomInteger = Math.floor(Math.random() * 3 + 1)
    const name = req.session.name;
    res.render("members", {pageTitle: 'members', name: name, randomInteger: randomInteger})
    
    // res.send(`<h1>Hello ${name}</h1> <img src="/thug${randomInteger}.jpeg"><a href="/logout"><button>Log Out</button></a>`);
    // console.log(req.session.cookie)
})

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect("/");
});

app.get('/admin', async (req, res) => {
    try {
        const result = await userCollection.find().toArray();
        res.render('admin', {pageTitle: 'admin', users: result});
    } catch (err) {
        console.log(err);
        res.send("Error");
    }
   
    
})

app.get("*", (req, res) => {
    res.send("404");
})

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});


