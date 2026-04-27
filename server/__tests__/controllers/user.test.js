/**
 * user.test.js
 * Updated for cookie-based auth (HttpOnly accessToken cookie).
 * Uses supertest.agent() per role to maintain cookie sessions across requests.
 * Status codes updated: RBAC denials now correctly expect 403 (not 401).
 */
const bcrypt = require("bcrypt");
const pool = require("../../config");
const supertest = require("supertest");
const app = require("../../app");
const { usersInDb } = require("../../helpers/test_helper");

// Supertest agents persist cookies across requests (simulates a browser session)
let adminAgent;
let customerAgent;

let adminUserId;
let customerUserId;

beforeEach(async () => {
  await pool.query("DELETE FROM users");

  const hashedPassword = await bcrypt.hash("Secret123!", 12);

  // Admin account
  const { rows: adminRows } = await pool.query(
    "INSERT INTO users(username, password, email, fullname, roles) VALUES($1, $2, $3, $4, $5) returning user_id",
    ["admin", hashedPassword, "admin@email.com", "admin", '{"customer", "admin"}']
  );
  adminUserId = adminRows[0].user_id;

  // Customer account
  const { rows: custRows } = await pool.query(
    "INSERT INTO users(username, password, email, fullname) VALUES($1, $2, $3, $4) returning user_id",
    ["customer", hashedPassword, "customer@email.com", "customer"]
  );
  customerUserId = custRows[0].user_id;

  // Create carts for each user (required for login to work)
  await pool.query("INSERT INTO cart(user_id) VALUES($1) ON CONFLICT DO NOTHING", [adminUserId]);
  await pool.query("INSERT INTO cart(user_id) VALUES($1) ON CONFLICT DO NOTHING", [customerUserId]);

  // Login with agents (cookies are stored automatically)
  adminAgent = supertest.agent(app);
  await adminAgent.post("/api/auth/login").send({
    email: "admin@email.com",
    password: "Secret123!",
  });

  customerAgent = supertest.agent(app);
  await customerAgent.post("/api/auth/login").send({
    email: "customer@email.com",
    password: "Secret123!",
  });
});

afterEach(async () => {
  await pool.query("DELETE FROM users");
});

describe("User controller", () => {
  // ── Create user ────────────────────────────────────────────────────────────

  describe("Add new user", () => {
    it("should create a new user if user is an admin", async () => {
      const usersAtStart = await usersInDb();
      const response = await adminAgent
        .post("/api/users")
        .send({
          fullname: "John Doe",
          password: "Secret123!",
          username: "johndoe",
          email: "johndoe@email.com",
        })
        .expect(201);

      const usersAtEnd = await adminAgent.get("/api/users");

      expect(response.body).toHaveProperty("status", "success");
      expect(response.body).toHaveProperty("user");
      expect(response.body.user).not.toHaveProperty("password");
      expect(usersAtEnd.body).toHaveLength(usersAtStart.length + 1);
    });

    it("should return 403 if user is not an admin", async () => {
      const response = await customerAgent
        .post("/api/users")
        .send({
          fullname: "John Doe",
          password: "Secret123!",
          username: "johndoe2",
          email: "johndoe2@email.com",
        })
        .expect(403);

      expect(response.body).toHaveProperty("status", "error");
      expect(response.body.message).toMatch(/admin/i);
    });
  });

  // ── Get user by ID ─────────────────────────────────────────────────────────

  describe("Get user by id", () => {
    it("should return a user if user is an admin", async () => {
      const response = await adminAgent
        .get(`/api/users/${customerUserId}`)
        .expect(200);

      expect(response.body).toHaveProperty("username");
      expect(response.body).toHaveProperty("email");
      expect(response.body).not.toHaveProperty("password");
    });

    it("should return user if user is the owner", async () => {
      const response = await customerAgent
        .get(`/api/users/${customerUserId}`)
        .expect(200);

      expect(response.body).toHaveProperty("username");
      expect(response.body).not.toHaveProperty("password");
    });

    it("should return 403 if user is not admin or owner", async () => {
      const response = await customerAgent
        .get(`/api/users/${adminUserId}`)
        .expect(403);

      expect(response.body).toHaveProperty("status", "error");
    });
  });

  // ── Get all users ──────────────────────────────────────────────────────────

  describe("Get all users", () => {
    it("should return all users in database if user is an admin", async () => {
      const initialUsers = await usersInDb();
      const response = await adminAgent
        .get("/api/users")
        .expect(200);

      expect(response.body).toHaveLength(initialUsers.length);
    });

    it("should return 403 if user is not an admin", async () => {
      const response = await customerAgent
        .get("/api/users")
        .expect(403);

      expect(response.body).toHaveProperty("status", "error");
      expect(response.body.message).toMatch(/admin/i);
    });
  });

  // ── Update user ────────────────────────────────────────────────────────────

  describe("Update user", () => {
    it("should update a user if user is an admin", async () => {
      const response = await adminAgent
        .put(`/api/users/${customerUserId}`)
        .send({
          username: "newUsername",
          email: "newEmail@email.com",
          fullname: "new man",
          address: "address here",
          city: "city here",
          state: "state here",
          country: "naija",
        })
        .expect(200);

      expect(response.body).toHaveProperty("username", "newUsername");
      expect(response.body).toHaveProperty("email", "newEmail@email.com");
      expect(response.body).toHaveProperty("fullname", "new man");
    });

    it("should update a user if user is the owner", async () => {
      const response = await customerAgent
        .put(`/api/users/${customerUserId}`)
        .send({
          username: "newcustUsername",
          email: "newcust@email.com",
          fullname: "new man",
          address: "address here",
          city: "city here",
          state: "state here",
          country: "naija",
        })
        .expect(200);

      expect(response.body).toHaveProperty("username", "newcustUsername");
    });

    it("should return 403 if user is not the owner or admin", async () => {
      const response = await customerAgent
        .put(`/api/users/${adminUserId}`)
        .send({ username: "hacker", email: "hacker@email.com", fullname: "hacker" })
        .expect(403);

      expect(response.body).toHaveProperty("status", "error");
    });
  });

  // ── Delete user ────────────────────────────────────────────────────────────

  describe("Delete user", () => {
    it("should delete a user if user is an admin", async () => {
      const usersAtStart = await usersInDb();

      await adminAgent
        .delete(`/api/users/${customerUserId}`)
        .expect(200);

      const usersAtEnd = await usersInDb();
      expect(usersAtEnd).toHaveLength(usersAtStart.length - 1);
    });

    it("should delete a user if user is the owner", async () => {
      const usersAtStart = await usersInDb();

      await customerAgent
        .delete(`/api/users/${customerUserId}`)
        .expect(200);

      const usersAtEnd = await usersInDb();
      expect(usersAtEnd).toHaveLength(usersAtStart.length - 1);
    });

    it("should return 403 if user is not the owner or admin", async () => {
      await customerAgent
        .delete(`/api/users/${adminUserId}`)
        .expect(403);

      const usersAtEnd = await usersInDb();
      const initialUsers = await usersInDb();
      expect(usersAtEnd).toHaveLength(initialUsers.length);
    });
  });
});

afterAll(async () => {
  pool.end();
});
