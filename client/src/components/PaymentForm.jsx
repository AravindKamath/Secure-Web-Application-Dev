import { Button, HelperText } from "@windmill/react-ui";
import API from "api/axios.config";
import { useCart } from "context/CartContext";
import { useUser } from "context/UserContext";
import { formatCurrency } from "helpers/formatCurrency";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import PulseLoader from "react-spinners/PulseLoader";
import OrderService from "services/order.service";

const PaymentForm = ({ previousStep, addressData }) => {
  const { cartSubtotal, cartTotal, cartData, setCartData } = useCart();
  const { userData } = useUser();
  const [error, setError] = useState();
  const [isProcessing, setIsProcessing] = useState(false);
  const navigate = useNavigate();

  const handlePayment = async () => {
    setError();
    setIsProcessing(true);

    try {
      // Step 1: Create Razorpay order on the backend
      const { data: order } = await API.post("/payment/order", {
        amount: (cartSubtotal * 100).toFixed(),
        currency: "INR",
      });

      // Step 2: Configure Razorpay Checkout options
      const options = {
        key: import.meta.env.VITE_RAZORPAY_KEY_ID,
        amount: order.amount,
        currency: order.currency,
        name: "Vantage",
        description: "Order Payment",
        order_id: order.id,
        prefill: {
          name: addressData?.fullname || "",
          email: addressData?.email || userData?.email || "",
        },
        handler: async (response) => {
          try {
            // Step 3: Verify payment signature on the backend
            await API.post("/payment/verify", {
              razorpay_order_id: response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature: response.razorpay_signature,
            });

            // Step 4: Create order record after successful verification
            await OrderService.createOrder(
              cartSubtotal,
              cartTotal,
              response.razorpay_payment_id,
              "RAZORPAY"
            );

            setCartData({ ...cartData, items: [] });
            setIsProcessing(false);
            navigate("/cart/success", {
              state: { fromPaymentPage: true },
            });
          } catch (verifyError) {
            setIsProcessing(false);
            setError({
              message: "Payment verification failed. Please contact support.",
            });
          }
        },
        modal: {
          ondismiss: () => {
            toast.error("Payment cancelled");
            setIsProcessing(false);
          },
        },
        theme: {
          color: "#01A982",
        },
      };

      // Step 2b: Open Razorpay checkout modal
      const rzp = new window.Razorpay(options);
      rzp.on("payment.failed", (response) => {
        setError({
          message: response.error.description || "Payment failed",
        });
        setIsProcessing(false);
      });
      rzp.open();
    } catch (err) {
      setIsProcessing(false);
      setError({
        message: "Unable to initiate payment. Please try again.",
      });
    }
  };

  return (
    <div className="w-full">
      <div className="rounded-3xl border border-neutral-200/80 bg-white/70 p-6 md:p-8 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
        <h2 className="text-xl font-bold tracking-tight text-neutral-950 dark:text-white border-b border-neutral-200/60 dark:border-neutral-800/60 pb-4">
          Payment Method
        </h2>

        {/* Secure Messaging Banner */}
        <div className="rounded-2xl border border-emerald-500/10 bg-emerald-500/5 p-4 dark:border-emerald-500/20 dark:bg-emerald-500/10 flex items-start gap-3">
          <div className="text-emerald-600 dark:text-emerald-400 mt-0.5">
            <svg
              className="h-5 w-5 stroke-2"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0110 0v4" />
            </svg>
          </div>
          <div>
            <h4 className="text-sm font-bold text-neutral-900 dark:text-white">
              Secure Checkout Gateway
            </h4>
            <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5 font-medium leading-relaxed">
              All transactions are encrypted and processed securely. We do not store your credit
              card information.
            </p>
          </div>
        </div>

        {/* Razorpay badge */}
        <div className="rounded-2xl border border-neutral-200 dark:border-neutral-850 p-5 bg-neutral-50/50 dark:bg-neutral-950/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-col gap-1">
            <span className="text-xs font-bold text-neutral-400 dark:text-neutral-500 uppercase tracking-wider">
              Selected Method
            </span>
            <span className="text-base font-extrabold text-neutral-900 dark:text-white flex items-center gap-2">
              Razorpay Secure Checkout
            </span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-blue-500/20 bg-blue-500/5 text-blue-600 dark:text-blue-400 text-xs font-bold w-fit">
            <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
            OFFICIAL PARTNER
          </div>
        </div>

        {error && (
          <HelperText className="text-xs italic text-red-500 dark:text-red-400" valid={false}>
            {error.message}
          </HelperText>
        )}

        {/* Action buttons */}
        <div className="flex justify-between items-center pt-4 border-t border-neutral-200/60 dark:border-neutral-800/60 mt-2">
          <Button
            onClick={previousStep}
            className="px-6 py-2.5 rounded-full border border-neutral-200 dark:border-neutral-850 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm transition-all"
          >
            ← Back
          </Button>

          <Button
            disabled={isProcessing}
            onClick={handlePayment}
            className="px-8 py-3 rounded-full bg-neutral-900 text-white font-semibold shadow-md hover:bg-neutral-800 hover:scale-[1.02] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center gap-2 transition-all duration-300"
          >
            {isProcessing ? (
              <PulseLoader size={8} color={"currentColor"} />
            ) : (
              `Pay ${formatCurrency(cartSubtotal)}`
            )}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default PaymentForm;
