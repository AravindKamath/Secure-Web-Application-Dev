import { Button, HelperText, Input, Label } from "@windmill/react-ui";
import API from "api/axios.config";
import { useUser } from "context/UserContext";
import Layout from "layout/Layout";
import { useRef, useState } from "react";
import { useForm } from "react-hook-form";
import toast from "react-hot-toast";
import { Link, Navigate, useLocation } from "react-router-dom";
import PulseLoader from "react-spinners/PulseLoader";

const Register = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const { state } = useLocation();
  const { isLoggedIn, setUserState } = useUser();
  const {
    register,
    formState: { errors },
    handleSubmit,
    watch,
  } = useForm();
  const password = useRef({});
  password.current = watch("password", "");

  const onSubmit = (data) => {
    const { password, password2, username, name, email } = data;
    setError("");
    if (password === password2) {
      setIsLoading(!isLoading);
      API.post("/auth/signup", {
        username,
        email,
        password,
        fullname: name,
      })
        .then(({ data }) => {
          setError("");
          toast.success("Account created successfully.");
          setTimeout(() => {
            setUserState(data);
            setIsLoading(!isLoading);
          }, 1000);
        })
        .catch(({ response }) => {
          setIsLoading(false);
          if (response?.data?.errors && response.data.errors.length > 0) {
            setError(response.data.errors.map((err) => err.message).join(", "));
          } else {
            setError(response?.data?.message || "An error occurred");
          }
        });
    } else {
      setError("Passwords don't match");
    }
  };

  if (isLoggedIn) {
    return <Navigate to={state?.from || "/"} />;
  }

  return (
    <Layout title="Create account">
      <div className="w-full min-h-[90vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl">
        {/* Background glow matching other redesigned pages */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

        <div className="relative w-full max-w-lg z-10">
          <form
            className="rounded-3xl border border-neutral-200/80 bg-white/70 p-8 md:p-10 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-5 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20"
            onSubmit={handleSubmit(onSubmit)}
          >
            {/* Heading Section */}
            <div className="text-center mb-2">
              <h1 className="text-3xl font-extrabold tracking-tight text-neutral-955 dark:text-white sm:text-4xl">
                Create Your Account
              </h1>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
                Join Vantage and start shopping premium products.
              </p>
            </div>

            {/* Username */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                <span>Username</span>
              </Label>
              <Input
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                type="text"
                name="username"
                placeholder="Choose a username"
                {...register("username", {
                  minLength: {
                    value: 3,
                    message: "Username must be at least 3 characters",
                  },
                  maxLength: {
                    value: 30,
                    message: "Username must be at most 30 characters",
                  },
                  pattern: {
                    value: /^[a-zA-Z0-9]+$/,
                    message: "Username must contain only letters and numbers",
                  },
                  required: "Username is required",
                })}
              />
              {errors?.username && (
                <HelperText
                  className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                  valid={false}
                >
                  {errors.username.message}
                </HelperText>
              )}
            </div>

            {/* Fullname */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                <span>Full Name</span>
              </Label>
              <Input
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                type="text"
                name="name"
                placeholder="Enter your full name"
                {...register("name", {
                  required: "Name cannot be empty",
                  minLength: {
                    value: 6,
                    message: "Name must be greater than 5 characters",
                  },
                })}
              />
              {errors.name && (
                <HelperText
                  className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                  valid={false}
                >
                  {errors.name.message}
                </HelperText>
              )}
            </div>

            {/* Email */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                <span>Email Address</span>
              </Label>
              <Input
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                type="email"
                name="email"
                placeholder="Enter your email address"
                {...register("email", {
                  required: "Email required",
                  pattern: {
                    // eslint-disable-next-line no-useless-escape
                    value: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/,
                    message: "Email not valid",
                  },
                })}
              />
              {errors.email && (
                <HelperText
                  className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                  valid={false}
                >
                  {errors.email.message}
                </HelperText>
              )}
            </div>

            {/* Password */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                <span>Password</span>
              </Label>
              <input
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                type="password"
                name="password"
                placeholder="••••••••"
                {...register("password", {
                  required: "Password required",
                  minLength: {
                    value: 8,
                    message: "Password must be at least 8 characters",
                  },
                  pattern: {
                    value:
                      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?])/,
                    message:
                      "Password must contain at least one uppercase, lowercase, number, and special character",
                  },
                })}
              />
              {errors.password && (
                <HelperText
                  className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                  valid={false}
                >
                  {errors.password.message}
                </HelperText>
              )}
            </div>

            {/* Confirm Password */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                <span>Confirm Password</span>
              </Label>
              <input
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                type="password"
                name="password2"
                placeholder="••••••••"
                {...register("password2", {
                  validate: (value) => value === password.current || "Passwords do not match",
                })}
              />
              {errors.password2 && (
                <HelperText
                  className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                  valid={false}
                >
                  {errors.password2.message}
                </HelperText>
              )}
            </div>

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full py-3.5 rounded-xl bg-neutral-900 text-white font-semibold shadow-lg hover:bg-neutral-800 hover:scale-[1.01] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center transition-all duration-300 mt-2"
            >
              {isLoading ? (
                <PulseLoader color={"currentColor"} size={8} loading={isLoading} />
              ) : (
                "Create Account"
              )}
            </Button>

            {error && (
              <HelperText
                className="text-xs italic text-red-500 dark:text-red-400 text-center"
                valid={false}
              >
                {error}
              </HelperText>
            )}

            {/* Login Section Footer */}
            <div className="border-t border-neutral-200/60 dark:border-neutral-800/60 pt-6 text-center">
              <p className="text-sm text-neutral-600 dark:text-neutral-400">
                Already have an account?{" "}
                <Link
                  to="/login"
                  className="font-bold text-neutral-955 dark:text-white hover:underline transition-all"
                >
                  Login
                </Link>
              </p>
            </div>
          </form>
        </div>
      </div>
    </Layout>
  );
};

export default Register;
