
var name = "nothing";

exports.setName = function(argName) {
    name = argName;
};

exports.sayHello = function() {
    console.log("Hello, " + name);
};


