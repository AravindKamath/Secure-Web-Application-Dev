import { Button, HelperText, Input, Label } from "@windmill/react-ui";
import { useUser } from "context/UserContext";
import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";

const PaymentForm = ({ next }) => {
  const { userData } = useUser();
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

  return (
    <div className="w-full">
      <form
        className="rounded-3xl border border-neutral-200/80 bg-white/70 p-6 md:p-8 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20"
        onSubmit={handleSubmit((data) => next(data))}
      >
        <h2 className="text-xl font-bold tracking-tight text-neutral-950 dark:text-white border-b border-neutral-200/60 dark:border-neutral-800/60 pb-4">
          Shipping Address
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Full Name */}
          <div className="flex flex-col gap-1.5 md:col-span-2">
            <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
              <span>Full Name</span>
            </Label>
            <Input
              disabled
              type="text"
              className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-neutral-100/50 text-neutral-450 dark:border-neutral-800 dark:bg-neutral-950/20 dark:text-neutral-500 cursor-not-allowed opacity-80"
              name="fullname"
              {...register("fullname", { required: "Required" })}
            />
            {errors.fullname && (
              <HelperText
                className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                valid={false}
              >
                {errors.fullname.message}
              </HelperText>
            )}
          </div>

          {/* Email Address */}
          <div className="flex flex-col gap-1.5 md:col-span-2">
            <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
              <span>Email Address</span>
            </Label>
            <Input
              disabled
              className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-neutral-100/50 text-neutral-450 dark:border-neutral-800 dark:bg-neutral-950/20 dark:text-neutral-500 cursor-not-allowed opacity-80"
              type="text"
              name="email"
              {...register("email", { required: "Required" })}
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

          {/* Street Address */}
          <div className="flex flex-col gap-1.5 md:col-span-2">
            <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
              <span>Street Address</span>
            </Label>
            <Input
              className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              type="text"
              name="address"
              placeholder="123 Luxury Way"
              {...register("address", { required: "Required" })}
            />
            {errors.address && (
              <HelperText
                className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                valid={false}
              >
                {errors.address.message}
              </HelperText>
            )}
          </div>

          {/* Country */}
          <div className="flex flex-col gap-1.5">
            <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
              <span>Country</span>
            </Label>
            <Input
              className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              type="text"
              name="country"
              placeholder="India"
              {...register("country", { required: "Required" })}
            />
            {errors.country && (
              <HelperText
                className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                valid={false}
              >
                {errors.country.message}
              </HelperText>
            )}
          </div>

          {/* State / Region */}
          <div className="flex flex-col gap-1.5">
            <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
              <span>State / Region</span>
            </Label>
            <Input
              className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              type="text"
              name="state"
              placeholder="Maharashtra"
              {...register("state", { required: "Required" })}
            />
            {errors.state && (
              <HelperText
                className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                valid={false}
              >
                {errors.state.message}
              </HelperText>
            )}
          </div>

          {/* City */}
          <div className="flex flex-col gap-1.5 md:col-span-2">
            <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
              <span>City</span>
            </Label>
            <Input
              className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-600 dark:focus:border-white dark:focus:ring-white transition duration-200"
              type="text"
              name="city"
              placeholder="Mumbai"
              {...register("city", { required: "Required" })}
            />
            {errors.city && (
              <HelperText
                className="mt-1 text-xs italic text-red-500 dark:text-red-400"
                valid={false}
              >
                {errors.city.message}
              </HelperText>
            )}
          </div>
        </div>

        {/* Buttons */}
        <div className="flex justify-between items-center pt-4 border-t border-neutral-200/60 dark:border-neutral-800/60 mt-4">
          <Button
            tag={Link}
            to="/cart"
            className="px-6 py-2.5 rounded-full border border-neutral-200 dark:border-neutral-850 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm transition-all"
          >
            ← Back to Cart
          </Button>
          <Button
            type="submit"
            className="px-8 py-2.5 rounded-full bg-neutral-900 text-white font-semibold shadow-md hover:bg-neutral-800 hover:scale-[1.02] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 transition-all duration-200"
          >
            Continue to Payment
          </Button>
        </div>
      </form>
    </div>
  );
};

export default PaymentForm;
