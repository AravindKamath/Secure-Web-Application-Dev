import { format, parseISO } from "date-fns";
import { formatCurrency } from "helpers/formatCurrency";
import Layout from "layout/Layout";
import { useEffect, useState } from "react";
import { useLocation, useParams } from "react-router-dom";
import orderService from "services/order.service";

const OrderDetails = () => {
  const { id } = useParams();
  const { state } = useLocation();
  const [items, setItems] = useState(null);

  useEffect(() => {
    orderService.getOrder(id).then((res) => setItems(res.data));
  }, [id]);

  const getStatusBadge = (status) => {
    const normalized = status?.toLowerCase() || "";
    
    if (normalized === "pending") {
      return "bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-400 border border-amber-200/50 dark:border-amber-900/50";
    }
    if (normalized === "paid" || normalized === "completed") {
      return "bg-green-100 text-green-800 dark:bg-green-950/40 dark:text-green-450 border border-green-200/50 dark:border-green-900/50";
    }
    if (normalized === "cancelled") {
      return "bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-400 border border-red-200/50 dark:border-red-900/50";
    }
    if (normalized === "processing") {
      return "bg-blue-105 text-blue-805 dark:bg-blue-950/40 dark:text-blue-400 border border-blue-200/50 dark:border-blue-900/50";
    }
    if (normalized === "delivered") {
      return "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-455 border border-emerald-200/50 dark:border-emerald-900/50";
    }
    
    return "bg-neutral-100 text-neutral-800 dark:bg-neutral-800/40 dark:text-neutral-450 border border-neutral-200/50 dark:border-neutral-700/50";
  };

  return (
    <Layout title="Order Details" loading={items === null}>
      <div className="w-full min-h-[85vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl">
        {/* Background glow matching Vantage theme */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

        <div className="relative w-full max-w-6xl z-10 flex flex-col gap-8 animate-fade-in">
          
          {/* Hero Order Summary Section */}
          <div className="rounded-3xl border border-neutral-200/80 bg-white/70 p-8 md:p-10 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col md:flex-row items-center justify-between gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
            <div className="flex flex-col gap-2 text-center md:text-left">
              <span className="text-xs font-extrabold uppercase tracking-widest text-neutral-400 dark:text-neutral-500">
                Order details
              </span>
              <h1 className="text-3xl sm:text-4xl font-black text-neutral-955 dark:text-white tracking-tight">
                Order #{state.order.order_id}
              </h1>
              <div className="flex flex-wrap items-center justify-center md:justify-start gap-3 mt-1.5">
                <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold tracking-wide capitalize ${getStatusBadge(state.order.status)}`}>
                  {state.order.status}
                </span>
                <span className="text-sm text-neutral-400 dark:text-neutral-500 font-medium">
                  Placed on {format(parseISO(state.order.date), "d MMM, yyyy")}
                </span>
              </div>
            </div>
            <div className="flex flex-col items-center md:items-end gap-1 text-center md:text-right">
              <span className="text-xs font-extrabold uppercase tracking-widest text-neutral-450 dark:text-neutral-550">
                Total Amount
              </span>
              <span className="text-3xl font-black text-[#01A982] dark:text-emerald-450">
                {formatCurrency(state.order.amount)}
              </span>
              <span className="text-sm text-neutral-500 dark:text-neutral-400 font-semibold mt-1">
                {`${state.order.total || 0} ${state.order.total === 1 ? "Item" : "Items"}`}
              </span>
            </div>
          </div>

          {/* Order Information Layout (Grid of Cards) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="flex flex-col gap-1.5 p-5 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
              <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">Order ID</span>
              <span className="text-sm font-bold text-neutral-850 dark:text-neutral-200">
                #{state.order.order_id}
              </span>
            </div>
            
            <div className="flex flex-col gap-1.5 p-5 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
              <span className="text-xs font-semibold text-neutral-455 dark:text-neutral-500">Total Items</span>
              <span className="text-sm font-bold text-neutral-855 dark:text-neutral-200">
                {state.order.total || 0} {state.order.total === 1 ? "Item" : "Items"}
              </span>
            </div>

            <div className="flex flex-col gap-1.5 p-5 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
              <span className="text-xs font-semibold text-neutral-455 dark:text-neutral-500">Total Amount</span>
              <span className="text-sm font-bold text-[#01A982] dark:text-emerald-450">
                {formatCurrency(state.order.amount)}
              </span>
            </div>

            <div className="flex flex-col gap-1.5 p-5 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
              <span className="text-xs font-semibold text-neutral-455 dark:text-neutral-500">Order Date</span>
              <span className="text-sm font-bold text-neutral-855 dark:text-neutral-200">
                {format(parseISO(state.order.date), "d MMM, yyyy")}
              </span>
            </div>
          </div>

          {/* Items in this Order */}
          <div className="flex flex-col gap-6 mt-4">
            <h2 className="text-xl font-extrabold text-neutral-955 dark:text-white tracking-tight border-b border-neutral-200/60 dark:border-neutral-800/60 pb-3">
              Items in this Order
            </h2>
            
            <div className="flex flex-col gap-6">
              {items?.map((item) => (
                <div
                  key={item.product_id}
                  className="rounded-3xl border border-neutral-200/80 bg-white/70 shadow-lg dark:border-white/10 dark:bg-neutral-900/60 p-6 flex flex-col md:flex-row gap-6 items-center md:items-start transition-all duration-300 hover:scale-[1.01] hover:border-neutral-350 dark:hover:border-white/20 hover:shadow-xl animate-fade-in"
                >
                  {/* Product Image */}
                  <div className="w-full md:w-1/3 lg:w-1/4 max-w-[200px] flex-shrink-0 flex items-center justify-center p-3 bg-white rounded-2xl border border-neutral-200/50 dark:border-neutral-850">
                    <img
                      className="h-36 object-contain"
                      loading="lazy"
                      decoding="async"
                      src={item.image_url}
                      alt={item.name}
                    />
                  </div>
                  
                  {/* Product Info */}
                  <div className="flex-grow flex flex-col gap-2 w-full text-center md:text-left">
                    <div className="flex flex-col md:flex-row items-center md:items-start justify-between gap-2">
                      <h3 className="text-lg font-bold text-neutral-950 dark:text-white leading-snug">
                        {item.name}
                      </h3>
                      <span className="text-lg font-black text-neutral-955 dark:text-white">
                        {formatCurrency(item.price)}
                      </span>
                    </div>
                    <p className="text-sm text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-2xl">
                      {item.description}
                    </p>
                    <div className="mt-2 flex justify-center md:justify-start">
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-neutral-100 dark:bg-neutral-850 text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700">
                        Qty: {item.quantity}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </Layout>
  );
};

export default OrderDetails;
