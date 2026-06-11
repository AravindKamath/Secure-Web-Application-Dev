import {
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHeader,
  TableRow,
} from "@windmill/react-ui";
import CartItem from "components/CartItem";
import { useCart } from "context/CartContext";
import { formatCurrency } from "helpers/formatCurrency";
import Layout from "layout/Layout";
import { ShoppingCart } from "react-feather";
import { Link } from "react-router-dom";

const Cart = () => {
  const { cartData, isLoading, cartSubtotal } = useCart();

  const itemCount = cartData?.items?.reduce((acc, item) => acc + item.quantity, 0) || 0;

  if (cartData?.items?.length === 0) {
    return (
      <Layout title="Cart" loading={isLoading}>
        <div className="relative w-full min-h-[70vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col justify-center items-center py-16 rounded-3xl overflow-hidden">
          {/* Background glow */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

          <div className="relative text-center max-w-md px-6 flex flex-col items-center">
            <div className="mb-6 p-6 rounded-full bg-neutral-100 dark:bg-neutral-900 border border-neutral-200/60 dark:border-neutral-800 text-neutral-400 dark:text-neutral-500 shadow-inner flex items-center justify-center">
              <ShoppingCart size={80} className="stroke-1" />
            </div>

            <h1 className="text-3xl font-extrabold tracking-tight text-neutral-950 dark:text-white mb-3">
              Your cart is empty
            </h1>

            <p className="text-neutral-500 dark:text-neutral-400 mb-8 max-w-sm">
              Looks like you haven't added anything to your cart yet. Head back to the store to
              explore our premium products.
            </p>

            <Button
              tag={Link}
              to="/"
              className="px-8 py-3.5 rounded-full bg-neutral-900 text-white font-semibold shadow-lg hover:bg-neutral-800 hover:scale-[1.02] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center gap-2 transition-all duration-300"
            >
              Continue Shopping →
            </Button>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout loading={isLoading || cartData === undefined}>
      <style type="text/css">{`
        .premium-cart-table {
          border-collapse: separate;
          border-spacing: 0 16px;
          background-color: transparent !important;
          width: 100%;
        }
        .premium-cart-table tr {
          transition: all 0.3s ease;
        }
        .premium-cart-table tbody tr {
          background-color: rgba(255, 255, 255, 0.7);
          box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
          border-radius: 16px;
        }
        .dark .premium-cart-table tbody tr {
          background-color: rgba(23, 23, 23, 0.6);
          box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }
        .premium-cart-table tbody tr:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -2px rgba(0, 0, 0, 0.04);
        }
        .premium-cart-table th {
          border: none !important;
          padding-bottom: 8px;
          font-size: 0.75rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.15em;
          color: #6b7280;
          background-color: transparent !important;
        }
        .dark .premium-cart-table th {
          color: #9ca3af;
        }
        .premium-cart-table td {
          padding: 24px 20px !important;
          border-top: 1px solid rgba(0, 0, 0, 0.05) !important;
          border-bottom: 1px solid rgba(0, 0, 0, 0.05) !important;
          color: #1f2937 !important;
          background-color: transparent !important;
        }
        .dark .premium-cart-table td {
          border-top: 1px solid rgba(255, 255, 255, 0.05) !important;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
          color: #f3f4f6 !important;
        }
        .premium-cart-table td:first-child {
          border-left: 1px solid rgba(0, 0, 0, 0.05) !important;
          border-top-left-radius: 16px;
          border-bottom-left-radius: 16px;
        }
        .dark .premium-cart-table td:first-child {
          border-left: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        .premium-cart-table td:last-child {
          border-right: 1px solid rgba(0, 0, 0, 0.05) !important;
          border-top-right-radius: 16px;
          border-bottom-right-radius: 16px;
        }
        .dark .premium-cart-table td:last-child {
          border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        
        /* Style inside buttons and quantities in CartItem */
        .premium-cart-table td button {
          border-radius: 9999px !important;
          transition: all 0.2s ease !important;
          border: 1px solid rgba(0, 0, 0, 0.1) !important;
        }
        .dark .premium-cart-table td button {
          border: 1px solid rgba(255, 255, 255, 0.1) !important;
          color: #fff !important;
        }
        .premium-cart-table td button:hover {
          background-color: #f3f4f6 !important;
        }
        .dark .premium-cart-table td button:hover {
          background-color: #262626 !important;
        }
      `}</style>

      <div className="w-full bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white rounded-3xl overflow-hidden">
        <section className="relative overflow-hidden py-10 md:py-16">
          {/* Background glow matching landing page */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

          <div className="relative mx-auto max-w-5xl px-4 sm:px-6">
            {/* Shopping Cart Header */}
            <div className="mb-10 text-center md:text-left">
              <h1 className="text-4xl font-black tracking-tight text-neutral-955 dark:text-white sm:text-5xl">
                Shopping Cart
              </h1>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
                Review your selected items before checkout.
              </p>
            </div>

            <div className="flex flex-col lg:flex-row gap-8 items-start">
              {/* Cart Items Section */}
              <div className="w-full lg:w-2/3">
                <TableContainer className="bg-transparent shadow-none border-none overflow-visible">
                  <div className="w-full overflow-x-auto">
                    <Table className="premium-cart-table">
                      <TableHeader>
                        <TableRow>
                          <TableCell>Product</TableCell>
                          <TableCell>Amount</TableCell>
                          <TableCell>Quantity</TableCell>
                          <TableCell>Total</TableCell>
                          <TableCell>Remove</TableCell>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {cartData?.items?.map((item) => (
                          <TableRow key={item.product_id}>
                            <CartItem item={item} />
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </TableContainer>
              </div>

              {/* Order Summary Card */}
              <div className="w-full lg:w-1/3">
                <div className="rounded-3xl border border-neutral-200/80 bg-white/70 p-6 md:p-8 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
                  <h2 className="text-xl font-bold tracking-tight text-neutral-950 dark:text-white border-b border-neutral-200/60 dark:border-neutral-800/60 pb-4">
                    Order Summary
                  </h2>

                  <div className="flex flex-col gap-4 text-sm font-medium">
                    <div className="flex justify-between text-neutral-500 dark:text-neutral-400">
                      <span>Items ({itemCount})</span>
                      <span>{formatCurrency(cartSubtotal)}</span>
                    </div>

                    <div className="flex justify-between text-neutral-500 dark:text-neutral-400">
                      <span>Shipping</span>
                      <span className="text-emerald-600 dark:text-emerald-500 font-bold">Free</span>
                    </div>

                    <div className="border-t border-neutral-200/60 dark:border-neutral-800/60 pt-4 flex justify-between items-center text-neutral-950 dark:text-white">
                      <span className="text-base font-bold">Total</span>
                      <span className="text-2xl font-black">{formatCurrency(cartSubtotal)}</span>
                    </div>
                  </div>

                  <Button
                    tag={Link}
                    to={"/cart/checkout"}
                    state={{
                      fromCartPage: true,
                    }}
                    className="w-full py-4 rounded-full bg-neutral-900 text-white font-semibold shadow-lg hover:bg-neutral-800 hover:scale-[1.02] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center gap-2 transition-all duration-300"
                  >
                    Proceed to Checkout
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </Layout>
  );
};

export default Cart;
