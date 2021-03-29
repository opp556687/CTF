const express = require('express');
const SECRET = require('./secret').SECRET;
const app = express();

app.get("/", (reqest, response) => {
    const command = reqest.query.command;
    if (command &&
        command.indexOf("shark") == -1 &&
        command.length < 3 &&
        command == "Baby shark, doo doo doo doo doo doo")
        response.send(SECRET);
    else
    response.send(`<center>
        <a href="/source" style="line-height:95vh;font-size:128px">A</a>
    </center>`);
})
app.get("/source", (_, response) => {
    response.sendFile(__filename);
})

app.listen(3000);
