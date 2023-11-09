const router = require("express").Router();
const User = require("../../dbconnection/models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const UTILS = require("./utils");
/**
 * Handle Sign up
 */
router.post("/signup", async (req, res) => {
  try {
    //Hashing the user's password before saving it to DB
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    //Create user with hashed password
    const createdUser = await User.create({
      email: req.body.email,
      password: hashedPassword,
    });
    console.log(createdUser);
    req.session.signinSuccess = true;
    res.json({
      ...createdUser,
      status: 200,
    });
  } catch (error) {
    // Handle any errors 
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

/**
 * Handle log in
 */
router.post("/login", async (req, res) => {
  const currentUser = await User.find({
    email: req.body.email,
    pwd: req.body.password,
  }).lean();
  // send tokenized user credential to decode on the front end.
  if (currentUser.length !== 0) {
    const token = jwt.sign(currentUser[0], "124", { mutatePayload: true });
    req.session.loginStatus = true;
    res.send({
      ...currentUser[0],
      token: true,
      authToken: token,
    });
  } else {
    req.session.loginStatus = false;
    res.send({ token: false });
  }
});
/**
 * Edit User
 */
router.post("/editUser", async (req, res) => {
  const userCred = jwt.decode(req.headers["x-access-token"]);
  let itemsToUpdate = UTILS.rmvEmpty(req.body);
  await User.findOneAndUpdate({ email: userCred.email }, itemsToUpdate).lean();
  const updatedUser = await User.findOne({ email: userCred.email }).lean();
  const token = jwt.sign({ ...updatedUser }, "124");
  res.send({
    ...updatedUser,
    token: true,
    authToken: token,
  });
});
module.exports = router;
