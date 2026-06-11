import AddressForm from "components/AddressForm";
import PaymentForm from "components/PaymentForm";
import { useCart } from "context/CartContext";
import { formatCurrency } from "helpers/formatCurrency";
import Layout from "layout/Layout";
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router";

const Checkout = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [addressData, setAddressData] = useState();
  const { state } = useLocation();
  const navigate = useNavigate();
  const { cartData, cartSubtotal } = useCart();

  useEffect(() => {
    if (!state?.fromCartPage) {
      return navigate("/cart");
    }

    if (cartData?.items?.length === 0) {
      return navigate("/cart");
    }
  }, [cartData, navigate, state]);

  const nextStep = () => setActiveStep((prevStep) => setActiveStep(prevStep + 1));
  const previousStep = () => setActiveStep((prevStep) => setActiveStep(prevStep - 1));

  const next = (data) => {
    setAddressData(data);
    nextStep();
  };

  return (
    <Layout loading={cartData === undefined}>
      <div className="w-full bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white rounded-3xl overflow-hidden">
        <section className="relative overflow-hidden py-10 md:py-16">
          {/* Background glow matching other redesigned pages */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

          <div className="relative mx-auto max-w-5xl px-4 sm:px-6">
            {/* Header Section */}
            <div className="mb-10 text-center md:text-left">
              <h1 className="text-4xl font-black tracking-tight text-neutral-950 dark:text-white sm:text-5xl">
                Secure Checkout
              </h1>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
                Complete your purchase in a few simple steps
              </p>
            </div>

            {/* Progress indicator */}
            <div className="mb-10 flex items-center justify-center md:justify-start gap-4 text-xs font-bold tracking-wider uppercase">
              <div
                className={`flex items-center gap-2 ${
                  activeStep === 0
                    ? "text-neutral-900 dark:text-white"
                    : "text-neutral-400 dark:text-neutral-500"
                }`}
              >
                <span
                  className={`flex h-6 w-6 items-center justify-center rounded-full border text-[10px] ${
                    activeStep === 0
                      ? "border-black bg-black text-white dark:border-white dark:bg-white dark:text-black"
                      : "border-neutral-300 bg-neutral-100 dark:border-neutral-800 dark:bg-neutral-950"
                  }`}
                >
                  1
                </span>
                <span>Address Details</span>
              </div>
              <span className="text-neutral-300 dark:text-neutral-700">→</span>
              <div
                className={`flex items-center gap-2 ${
                  activeStep === 1
                    ? "text-neutral-900 dark:text-white"
                    : "text-neutral-400 dark:text-neutral-500"
                }`}
              >
                <span
                  className={`flex h-6 w-6 items-center justify-center rounded-full border text-[10px] ${
                    activeStep === 1
                      ? "border-black bg-black text-white dark:border-white dark:bg-white dark:text-black"
                      : "border-neutral-300 bg-neutral-100 dark:border-neutral-800 dark:bg-neutral-950"
                  }`}
                >
                  2
                </span>
                <span>Payment</span>
              </div>
            </div>

            {/* Two-column layout grid */}
            <div className="flex flex-col lg:flex-row gap-8 items-start">
              {/* Left column: Address / Payment form */}
              <div className="w-full lg:w-2/3">
                {activeStep === 0 ? (
                  <AddressForm next={next} />
                ) : (
                  <PaymentForm
                    nextStep={nextStep}
                    previousStep={previousStep}
                    addressData={addressData}
                  />
                )}
              </div>

              {/* Right column: Order Summary Card */}
              <div className="w-full lg:w-1/3">
                <div className="rounded-3xl border border-neutral-200/80 bg-white/70 p-6 md:p-8 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
                  <h2 className="text-xl font-bold tracking-tight text-neutral-955 dark:text-white border-b border-neutral-200/60 dark:border-neutral-800/60 pb-4">
                    Order Items
                  </h2>

                  <div className="flex flex-col gap-4 overflow-y-auto max-h-[40vh] pr-2">
                    {cartData?.items?.map((item) => (
                      <div
                        key={item.product_id}
                        className="flex gap-4 items-center py-2 border-b border-neutral-100 dark:border-neutral-800/40 last:border-none"
                      >
                        <div className="relative h-16 w-16 overflow-hidden rounded-xl bg-neutral-50 dark:bg-neutral-950 border border-neutral-200/50 dark:border-neutral-850 flex items-center justify-center flex-shrink-0">
                          <img
                            className="max-h-[85%] max-w-[85%] object-contain"
                            loading="lazy"
                            decoding="async"
                            src={item.image_url}
                            alt={item.name}
                          />
                        </div>
                        <div className="flex flex-col flex-grow min-w-0">
                          <span className="text-sm font-bold text-neutral-900 dark:text-white truncate">
                            {item.name}
                          </span>
                          <span className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5 font-medium">
                            Qty: {item.quantity}
                          </span>
                        </div>
                        <div className="text-sm font-extrabold text-neutral-955 dark:text-white">
                          {formatCurrency(item.price * item.quantity)}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div className="border-t border-neutral-200/60 dark:border-neutral-800/60 pt-4 flex flex-col gap-3 text-sm font-medium">
                    <div className="flex justify-between text-neutral-500 dark:text-neutral-400">
                      <span>Subtotal</span>
                      <span>{formatCurrency(cartSubtotal)}</span>
                    </div>
                    <div className="flex justify-between text-neutral-500 dark:text-neutral-400">
                      <span>Shipping</span>
                      <span className="text-emerald-600 dark:text-emerald-500 font-bold">Free</span>
                    </div>
                    <div className="border-t border-neutral-200/60 dark:border-neutral-800/60 pt-3 flex justify-between items-center text-neutral-955 dark:text-white">
                      <span className="text-base font-bold">Total</span>
                      <span className="text-2xl font-black">{formatCurrency(cartSubtotal)}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </Layout>
  );
};

export default Checkout;
