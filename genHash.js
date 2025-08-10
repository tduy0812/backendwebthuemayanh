// genHash.js
const bcrypt = require("bcryptjs");
const pwd = process.argv[2] || "haha";
const saltRounds = 10;
bcrypt.hash(pwd, saltRounds)
    .then(hash => {
        console.log("Hash for password:", pwd);
        console.log(hash);
        process.exit(0);
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
