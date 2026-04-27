const router = require("express").Router();
const {
  getAllUsers,
  createUser,
  deleteUser,
  getUserById,
  updateUser,
  getUserProfile,
} = require("../controllers/users.controller");
const verifyAdmin = require("../middleware/verifyAdmin");
const verifyToken = require("../middleware/verifyToken");
const validate = require("../middleware/validate");
const { updateUserSchema, createUserSchema } = require("../validators/user.validators");

// All user routes require a valid access token
router.use(verifyToken);

// Admin-only: list all users, create a user
router
  .route("/")
  .get(verifyAdmin, getAllUsers)
  .post(verifyAdmin, validate(createUserSchema), createUser);

// Authenticated user: get own profile
router.route("/profile").get(getUserProfile);

// Self-or-admin: get, update, delete a specific user
router
  .route("/:id")
  .get(getUserById)
  .put(validate(updateUserSchema), updateUser)
  .delete(deleteUser);

module.exports = router;
