import { Button, HelperText, Input, Label } from "@windmill/react-ui";
import { useUser } from "context/UserContext";
import { useState } from "react";
import { useForm } from "react-hook-form";
import PulseLoader from "react-spinners/PulseLoader";

const AccountForm = ({ setShowSettings, userData }) => {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    defaultValues: {
      fullname: userData?.fullname,
      email: userData?.email,
      username: userData?.username,
      address: userData?.address,
      country: userData?.country,
      city: userData?.city,
      state: userData?.state,
    },
  });
  const [validationError, setValidationError] = useState();
  const [isSaving, setIsSaving] = useState(false);
  const { updateUserData } = useUser();

  const onSubmit = async (data) => {
    setValidationError();
    setIsSaving(true);
    try {
      await updateUserData(data);
      setShowSettings(false);
      setIsSaving(false);
    } catch (error) {
      setIsSaving(false);
      setValidationError(error.response?.data?.message);
    }
  };

  return (
    <div className="w-full min-h-[80vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl">
      {/* Background glow matching Vantage theme */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

      <div className="relative w-full max-w-2xl z-10">
        <form
          onSubmit={handleSubmit(onSubmit)}
          className="rounded-3xl border border-neutral-200/80 bg-white/70 p-8 md:p-10 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20"
        >
          {/* Header */}
          <div className="mb-2">
            <h2 className="text-2xl font-extrabold tracking-tight text-neutral-950 dark:text-white sm:text-3xl">
              Edit Profile
            </h2>
            <p className="mt-1.5 text-sm text-neutral-500 dark:text-neutral-400">
              Update your personal information
            </p>
          </div>

          {/* Form Layout */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            
            {/* Full Name */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-705 dark:text-neutral-300">
                <span>Full Name</span>
              </Label>
              <Input
                name="fullname"
                {...register("fullname")}
                placeholder="Enter your full name"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
            </div>

            {/* Username */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-705 dark:text-neutral-300">
                <span>Username</span>
              </Label>
              <Input
                name="username"
                {...register("username")}
                placeholder="Enter your username"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
              {validationError?.username && (
                <HelperText className="mt-1 text-xs italic text-red-500 dark:text-red-400" valid={false}>
                  {validationError.username}
                </HelperText>
              )}
            </div>

            {/* Email */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-705 dark:text-neutral-300">
                <span>Email Address</span>
              </Label>
              <Input
                name="email"
                {...register("email", {
                  required: "Email required",
                  pattern: {
                    // eslint-disable-next-line no-useless-escape
                    value: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/,
                    message: "Email not valid",
                  },
                })}
                placeholder="Enter your email address"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
              {errors.email && (
                <HelperText className="mt-1 text-xs italic text-red-500 dark:text-red-400" valid={false}>
                  {errors.email.message}
                </HelperText>
              )}
              {validationError?.email && (
                <HelperText className="mt-1 text-xs italic text-red-500 dark:text-red-400" valid={false}>
                  {validationError.email}
                </HelperText>
              )}
            </div>

            {/* Address */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-705 dark:text-neutral-300">
                <span>Address</span>
              </Label>
              <Input
                name="address"
                {...register("address")}
                placeholder="Street address"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
            </div>

            {/* City */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-755 dark:text-neutral-300">
                <span>City</span>
              </Label>
              <Input
                name="city"
                {...register("city")}
                placeholder="City"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
            </div>

            {/* State */}
            <div className="flex flex-col gap-1.5">
              <Label className="text-sm font-semibold text-neutral-755 dark:text-neutral-300">
                <span>State</span>
              </Label>
              <Input
                name="state"
                {...register("state")}
                placeholder="State / Province"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
            </div>

            {/* Country */}
            <div className="flex flex-col gap-1.5 md:col-span-2">
              <Label className="text-sm font-semibold text-neutral-755 dark:text-neutral-300">
                <span>Country</span>
              </Label>
              <Input
                name="country"
                {...register("country")}
                placeholder="Country"
                className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              />
            </div>

          </div>

          {/* Buttons */}
          <div className="flex justify-end items-center gap-3 pt-6 border-t border-neutral-200/60 dark:border-neutral-800/60 mt-4">
            <Button
              disabled={isSaving}
              onClick={() => setShowSettings(false)}
              layout="outline"
              className="px-6 py-3 rounded-xl border border-neutral-200 dark:border-neutral-800 text-neutral-700 dark:text-neutral-300 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm transition-all focus:outline-none"
            >
              Cancel
            </Button>
            <Button
              disabled={isSaving}
              type="submit"
              className="px-6 py-3 rounded-xl bg-[#01A982] text-white hover:bg-[#019371] font-semibold shadow-lg transition-all duration-300 hover:scale-[1.01] active:scale-95 focus:outline-none flex items-center justify-center gap-2 min-w-[140px]"
            >
              {isSaving ? (
                <PulseLoader color={"#ffffff"} size={8} loading={isSaving} />
              ) : (
                "Save Changes"
              )}
            </Button>
          </div>

        </form>
      </div>
    </div>
  );
};

export default AccountForm;
