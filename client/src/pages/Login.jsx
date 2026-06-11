import { useGoogleLogin } from "@react-oauth/google";
import { Button, HelperText, Input, Label } from "@windmill/react-ui";
import ForgotPasswordModal from "components/ForgotPasswordModal";
import { useUser } from "context/UserContext";
import Layout from "layout/Layout";
import { useState } from "react";
import { useForm } from "react-hook-form";
import toast from "react-hot-toast";
import { Link, Navigate, useLocation } from "react-router-dom";
import PulseLoader from "react-spinners/PulseLoader";
import authService from "services/auth.service";

const Login = () => {
  const { isLoggedIn, setUserState } = useUser();
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [redirectToReferrer, setRedirectToReferrer] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaToken, setMfaToken] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaError, setMfaError] = useState("");
  const [isMfaSubmitting, setIsMfaSubmitting] = useState(false);
  const { state } = useLocation();

  const login = useGoogleLogin({
    onSuccess: (codeResponse) => handleGoogleLogin(codeResponse),
    onError: (error) => console.log("Login Failed:", error),
    flow: "auth-code",
  });

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    defaultValues: {
      email: "",
      password: "",
    },
  });

  async function handleGoogleLogin(googleData) {
    try {
      const data = await authService.googleLogin(googleData.code);
      toast.success("Login successful 🔓");

      setUserState(data);
      setRedirectToReferrer(true);
      setIsGoogleLoading(false);
    } catch (error) {
      setIsGoogleLoading(false);
      toast.error("Could not login with Google 😢");
    }
  }

  const onSubmit = async (data) => {
    const { email, password } = data;

    try {
      setError("");
      setIsLoading(true);
      const data = await authService.login(email, password);

      if (data?.mfa_required) {
        setIsLoading(false);
        setMfaRequired(true);
        setMfaToken(data.mfa_token || "");
        setMfaError("");
        toast.success("MFA required. Enter your code to continue.");
        return;
      }

      toast.success("Login successful 🔓");

      setTimeout(() => {
        setUserState(data);
        setRedirectToReferrer(true);
        setIsLoading(false);
      }, 1500);
    } catch (error) {
      setIsLoading(false);
      const res = error.response;
      if (res?.data?.errors && res.data.errors.length > 0) {
        setError(res.data.errors.map((err) => err.message).join(", "));
      } else {
        setError(res?.data?.message || "An error occurred");
      }
    }
  };

  const handleMfaLogin = async (event) => {
    event.preventDefault();
    if (!mfaToken || !mfaCode) {
      setMfaError("MFA code is required");
      return;
    }

    try {
      setMfaError("");
      setIsMfaSubmitting(true);
      const data = await authService.loginMfa(mfaToken, mfaCode);
      toast.success("Login successful 🔓");
      setUserState(data);
      setRedirectToReferrer(true);
    } catch (error) {
      const res = error.response;
      setMfaError(res?.data?.message || "Unable to verify MFA code");
    } finally {
      setIsMfaSubmitting(false);
    }
  };

  const resetMfaState = () => {
    setMfaRequired(false);
    setMfaToken("");
    setMfaCode("");
    setMfaError("");
  };

  if (redirectToReferrer) {
    return <Navigate to={state?.from || "/"} />;
  }
  if (isLoggedIn) {
    return <Navigate to={state?.from || "/"} />;
  }

  return (
    <Layout title="Login">
      <style type="text/css">{`
        /* Style Forgot password? link inside ForgotPasswordModal */
        div span.cursor-pointer.text-purple-700 {
          color: #4f46e5 !important;
          font-weight: 600 !important;
          font-size: 0.875rem !important;
          transition: all 0.2s ease;
        }
        .dark div span.cursor-pointer.text-purple-700 {
          color: #818cf8 !important;
        }
        div span.cursor-pointer.text-purple-700:hover {
          color: #3730a3 !important;
          text-decoration: underline !important;
        }
        .dark div span.cursor-pointer.text-purple-700:hover {
          color: #a5b4fc !important;
        }
      `}</style>

      <div className="w-full min-h-[80vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl">
        {/* Background glow matching other redesigned pages */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

        <div className="relative w-full max-w-lg z-10">
          <form
            className="rounded-3xl border border-neutral-200/80 bg-white/70 p-8 md:p-10 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20"
            onSubmit={mfaRequired ? handleMfaLogin : handleSubmit(onSubmit)}
          >
            {/* Heading Section */}
            <div className="text-center mb-2">
              <h1 className="text-3xl font-extrabold tracking-tight text-neutral-950 dark:text-white sm:text-4xl">
                {mfaRequired ? "MFA Verification" : "Welcome Back"}
              </h1>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
                {mfaRequired
                  ? "Enter your security code to complete verification."
                  : "Sign in to your account to continue shopping."}
              </p>
            </div>

            {mfaRequired ? (
              <div className="flex flex-col gap-5">
                <div className="flex flex-col gap-2">
                  <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                    <span>MFA Code</span>
                  </Label>
                  <Input
                    className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200 text-center tracking-[0.3em] text-lg font-bold"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(event) => setMfaCode(event.target.value)}
                    placeholder="000000"
                  />
                  {mfaError && (
                    <HelperText
                      className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                      valid={false}
                    >
                      {mfaError}
                    </HelperText>
                  )}
                </div>

                <Button
                  type="submit"
                  disabled={isMfaSubmitting}
                  className="w-full py-3.5 rounded-xl bg-neutral-900 text-white font-semibold shadow-lg hover:bg-neutral-800 hover:scale-[1.01] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center transition-all duration-300"
                >
                  {isMfaSubmitting ? (
                    <PulseLoader color={"currentColor"} size={8} loading />
                  ) : (
                    "Verify and Continue"
                  )}
                </Button>

                <button
                  type="button"
                  onClick={resetMfaState}
                  className="w-full text-center text-sm font-semibold text-neutral-500 hover:text-neutral-800 dark:text-neutral-400 dark:hover:text-white transition-colors py-2"
                >
                  Back to login
                </button>
              </div>
            ) : (
              <div className="flex flex-col gap-5">
                {/* Email Address */}
                <div className="flex flex-col gap-2">
                  <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                    <span>Email Address</span>
                  </Label>
                  <Input
                    className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                    type="email"
                    name="email"
                    {...register("email", {
                      required: true,
                      // eslint-disable-next-line no-useless-escape
                      pattern: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/,
                    })}
                    placeholder="Enter your email address"
                  />
                  {errors?.email && errors?.email.type === "required" && (
                    <HelperText
                      className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                      valid={false}
                    >
                      Email is required
                    </HelperText>
                  )}
                  {errors?.email && errors?.email.type === "pattern" && (
                    <HelperText
                      className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                      valid={false}
                    >
                      Please enter a valid email address
                    </HelperText>
                  )}
                </div>

                {/* Password */}
                <div className="flex flex-col gap-2">
                  <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                    <span>Password</span>
                  </Label>
                  <input
                    className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
                    type="password"
                    name="password"
                    placeholder="••••••••"
                    {...register("password", { required: true })}
                  />
                  {errors?.password && (
                    <HelperText
                      className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                      valid={false}
                    >
                      {errors?.password?.type === "required" && "Password is required"}
                    </HelperText>
                  )}
                </div>

                {error && (
                  <HelperText
                    className="text-xs italic text-red-500 dark:text-red-400"
                    valid={false}
                  >
                    {error}
                  </HelperText>
                )}

                {/* Forgot Password Link Container */}
                <div className="flex items-center justify-end">
                  <ForgotPasswordModal />
                </div>

                {/* Buttons Container */}
                <div className="flex flex-col gap-3 mt-2">
                  <Button
                    type="submit"
                    disabled={isLoading || isGoogleLoading}
                    className="w-full py-3.5 rounded-xl bg-neutral-900 text-white font-semibold shadow-lg hover:bg-neutral-800 hover:scale-[1.01] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center transition-all duration-300"
                  >
                    {isLoading ? <PulseLoader color={"currentColor"} size={8} loading /> : "Login"}
                  </Button>

                  {/* Or Divider */}
                  <div className="relative flex py-2 items-center">
                    <div className="flex-grow border-t border-neutral-200 dark:border-neutral-800"></div>
                    <span className="flex-shrink mx-4 text-xs text-neutral-400 font-semibold uppercase tracking-wider">
                      Or
                    </span>
                    <div className="flex-grow border-t border-neutral-200 dark:border-neutral-800"></div>
                  </div>

                  {/* Google Sign In */}
                  <Button
                    type="button"
                    layout="link"
                    onClick={() => {
                      setIsGoogleLoading(true);
                      login();
                    }}
                    disabled={isLoading || isGoogleLoading}
                    className="w-full flex items-center justify-center gap-3 px-5 py-3.5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-950 font-semibold text-sm text-neutral-700 dark:text-neutral-300 shadow-md hover:bg-neutral-50 dark:hover:bg-neutral-900 transition-all duration-200"
                  >
                    <svg
                      className="w-5 h-5"
                      aria-hidden="true"
                      focusable="false"
                      data-prefix="fab"
                      data-icon="google"
                      role="img"
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 488 512"
                    >
                      <path
                        fill="currentColor"
                        d="M488 261.8C488 403.3 391.1 504 248 504 110.8 504 0 393.2 0 256S110.8 8 248 8c66.8 0 123 24.5 166.3 64.9l-67.5 64.9C258.5 52.6 94.3 116.6 94.3 256c0 86.5 69.1 156.6 153.7 156.6 98.2 0 135-70.4 140.8-106.9H248v-85.3h236.1c2.3 12.7 3.9 24.9 3.9 41.4z"
                      ></path>
                    </svg>
                    {isGoogleLoading ? (
                      <PulseLoader color={"currentColor"} size={8} loading />
                    ) : (
                      "Continue with Google"
                    )}
                  </Button>
                </div>

                {/* Sign Up Section Footer */}
                <div className="border-t border-neutral-200/60 dark:border-neutral-800/60 pt-6 text-center">
                  <p className="text-sm text-neutral-600 dark:text-neutral-400">
                    Don&apos;t have an account?{" "}
                    <Link
                      to="/signup"
                      className="font-bold text-neutral-955 dark:text-white hover:underline transition-all"
                    >
                      Sign Up
                    </Link>
                  </p>
                </div>
              </div>
            )}
          </form>
        </div>
      </div>
    </Layout>
  );
};

export default Login;
