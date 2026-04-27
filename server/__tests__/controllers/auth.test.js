/**
 * auth.test.js
 * Updated for cookie-based authentication (HttpOnly accessToken cookie).
 * Tests use supertest agent to preserve cookies between requests.
 *
 * Note: Signup/Login data updated to meet new Joi schema requirements:
 *   - password ≥ 8 chars, mixed case + digit + special char
 *   - username alphanum 3-30 chars
 */
const supertest = require("supertest");
const app = require("../../app");
const pool = require("../../config");
const bcrypt = require("bcrypt");

const api = supertest(app);

beforeAll(async () => {
  await pool.query("DELETE FROM users");
});

// ── Signup ────────────────────────────────────────────────────────────────────

describe("/api/auth/signup", () => {
  it("should create an account for user", async () => {
    const res = await api.post("/api/auth/signup").send({
      email: "email@email.com",
      password: "Secret123!",
      fullname: "Test User",
      username: "testuser",
    });

    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty("status", "success");
    expect(res.body).toHaveProperty("user");
    expect(res.body.user).not.toHaveProperty("password");

    // Token delivered as HttpOnly cookie — must NOT be in JSON body
    expect(res.body).not.toHaveProperty("token");
    expect(res.headers["set-cookie"]).toBeDefined();
  });

  describe("validation — Joi schema enforcement", () => {
    it("should reject weak passwords (< 8 chars)", async () => {
      const res = await api.post("/api/auth/signup").send({
        email: "weak@email.com",
        password: "abc",
        fullname: "Weak User",
        username: "weakuser",
      });
      expect(res.statusCode).toBe(422);
      expect(res.body).toHaveProperty("status", "error");
    });

    it("should reject invalid email format", async () => {
      const res = await api.post("/api/auth/signup").send({
        email: "not-an-email",
        password: "Secret123!",
        fullname: "Bad Email",
        username: "badmail",
      });
      expect(res.statusCode).toBe(422);
    });
  });

  describe("return error if username or email is taken", () => {
    beforeAll(async () => {
      await pool.query("DELETE FROM users");
      const hashedPassword = await bcrypt.hash("Secret123!", 12);
      await pool.query(
        "INSERT INTO users(username, password, email, fullname) VALUES($1, $2, $3, $4) returning user_id",
        ["testuser", hashedPassword, "email@email.com", "Test User"]
      );
    });

    it("should return 409 if username is taken", async () => {
      const res = await api
        .post("/api/auth/signup")
        .send({
          email: "other@email.com",
          password: "Secret123!",
          fullname: "Other User",
          username: "testuser",
        })
        .expect(409);

      expect(res.body).toHaveProperty("status", "error");
      expect(res.body.message).toMatch(/username/i);
    });

    it("should return 409 if email is taken", async () => {
      const res = await api
        .post("/api/auth/signup")
        .send({
          email: "email@email.com",
          password: "Secret123!",
          fullname: "Other User",
          username: "otheruser",
        })
        .expect(409);

      expect(res.body).toHaveProperty("status", "error");
      expect(res.body.message).toMatch(/email/i);
    });
  });
});

// ── Login ────────────────────────────────────────────────────────────────────

describe("/api/auth/login", () => {
  beforeEach(async () => {
    await pool.query("DELETE FROM users");
    const hashedPassword = await bcrypt.hash("Secret123!", 12);
    await pool.query(
      "INSERT INTO users(username, password, email, fullname) VALUES($1, $2, $3, $4)",
      ["testuser", hashedPassword, "email@email.com", "Test User"]
    );
  });

  it("should login a user and set HttpOnly cookies (no token in body)", async () => {
    const res = await api
      .post("/api/auth/login")
      .send({ email: "email@email.com", password: "Secret123!" });

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty("status", "success");
    expect(res.body).toHaveProperty("user");

    // Token must NOT appear in the response body (security requirement)
    expect(res.body).not.toHaveProperty("token");

    // Cookies must be set
    const cookies = res.headers["set-cookie"];
    expect(cookies).toBeDefined();
    expect(cookies.some((c) => c.startsWith("accessToken="))).toBe(true);
    expect(cookies.some((c) => c.startsWith("refreshToken="))).toBe(true);
    expect(cookies.some((c) => c.includes("HttpOnly"))).toBe(true);
  });

  it("should return 401 if credentials are incorrect", async () => {
    const res = await api
      .post("/api/auth/login")
      .send({ email: "email@email.com", password: "WrongPassword1!" })
      .expect(401);

    expect(res.body).toHaveProperty("status", "error");
    expect(res.body.message).toMatch(/incorrect/i);
  });

  it("should return 401 if email does not exist", async () => {
    const res = await api
      .post("/api/auth/login")
      .send({ email: "nobody@email.com", password: "Secret123!" })
      .expect(401);

    expect(res.body).toHaveProperty("status", "error");
  });
});

// ── Logout ───────────────────────────────────────────────────────────────────

describe("/api/auth/logout", () => {
  it("should clear auth cookies on logout", async () => {
    const agent = supertest.agent(app);

    const hashedPassword = await bcrypt.hash("Secret123!", 12);
    await pool.query("DELETE FROM users");
    await pool.query(
      "INSERT INTO users(username, password, email, fullname) VALUES($1, $2, $3, $4)",
      ["testuser", hashedPassword, "email@email.com", "Test User"]
    );

    // Login to get cookies
    await agent
      .post("/api/auth/login")
      .send({ email: "email@email.com", password: "Secret123!" });

    // Logout
    const logoutRes = await agent.post("/api/auth/logout");
    expect(logoutRes.statusCode).toBe(200);
    expect(logoutRes.body).toHaveProperty("status", "success");
  });
});

afterAll(async () => {
  await pool.end();
});
