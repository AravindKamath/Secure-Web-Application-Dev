import { Button } from "@windmill/react-ui";
import { useCart } from "context/CartContext";
import { formatCurrency } from "helpers/formatCurrency";
import Layout from "layout/Layout";
import { useEffect, useState } from "react";
import { ShoppingCart } from "react-feather";
import toast from "react-hot-toast";
import ReactStars from "react-rating-stars-component";
import { useNavigate, useParams } from "react-router-dom";
import { ClipLoader } from "react-spinners";
import productService from "services/product.service";

const ProductDetails = () => {
  const { slug } = useParams();
  const [product, setProduct] = useState(null);
  const navigate = useNavigate();
  const { addItem } = useCart();
  const [isLoading, setIsLoading] = useState(false);
  const [isFetching, setIsFetching] = useState(false);

  const addToCart = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await addItem(product, 1);
      toast.success("Added to cart");
    } catch (error) {
      console.log(error);
      toast.error("Error adding to cart");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    async function fetchData() {
      setIsFetching(true);
      try {
        const { data: product } = await productService.getProduct(slug);
        setProduct(product);
      } catch (error) {
        return navigate("/404", {
          replace: true,
        });
      } finally {
        setIsFetching(false);
      }
    }
    fetchData();
  }, [slug]);

  return (
    <Layout loading={isFetching} title={product?.name}>
      <div className="w-full bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white rounded-3xl overflow-hidden">
        <section className="relative overflow-hidden py-10 md:py-16">
          {/* Background glow matching landing page */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

          <div className="relative mx-auto max-w-5xl px-4 sm:px-6">
            <div className="flex flex-col lg:flex-row gap-8 lg:gap-12 items-stretch">
              {/* Product Image Container */}
              <div className="w-full lg:w-1/2 flex items-center justify-center">
                <div className="relative w-full aspect-square overflow-hidden rounded-3xl bg-neutral-50 dark:bg-neutral-900 border border-neutral-200/60 dark:border-neutral-800 shadow-sm transition-all duration-500 hover:shadow-xl hover:scale-[1.01] group flex items-center justify-center">
                  <img
                    decoding="async"
                    loading="lazy"
                    src={product?.image_url}
                    alt={product?.name}
                    className="max-h-[85%] max-w-[85%] object-contain p-4 transition-transform duration-500 ease-out group-hover:scale-105"
                  />
                </div>
              </div>

              {/* Product Info Glassmorphic Card */}
              <div className="w-full lg:w-1/2 flex flex-col justify-between">
                <div className="h-full rounded-3xl border border-neutral-200/80 bg-white/70 p-6 md:p-8 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col justify-between gap-6 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
                  <div className="flex flex-col gap-5">
                    {/* Badge */}
                    <div>
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-black/10 bg-black/5 px-3.5 py-1.5 text-xs font-semibold tracking-[0.15em] text-neutral-700 backdrop-blur dark:border-white/10 dark:bg-white/5 dark:text-neutral-300">
                        PREMIUM PRODUCT
                      </span>
                    </div>

                    {/* Product Title */}
                    <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-neutral-950 dark:text-white leading-tight">
                      {product?.name}
                    </h1>

                    {/* Rating Section - modern and clean */}
                    <div className="flex items-center gap-3 py-2 border-y border-neutral-200/60 dark:border-neutral-800/60">
                      <ReactStars
                        count={5}
                        size={20}
                        edit={false}
                        value={+product?.avg_rating || 0}
                        activeColor="#ffd700"
                      />
                      <span className="text-sm font-semibold text-neutral-600 dark:text-neutral-400 mt-0.5">
                        {+product?.avg_rating ? (+product.avg_rating).toFixed(1) : "0.0"}
                      </span>
                      <span className="text-neutral-300 dark:text-neutral-700">|</span>
                      <span className="text-sm font-semibold text-neutral-600 dark:text-neutral-400 mt-0.5">
                        {+product?.count > 0 ? `${+product.count} Ratings` : "No ratings"}
                      </span>
                    </div>

                    {/* Description Card */}
                    <div className="rounded-2xl border border-neutral-200/50 bg-neutral-100/40 p-5 dark:border-neutral-800/40 dark:bg-neutral-950/40 shadow-inner">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 mb-2">
                        Product Description
                      </h3>
                      <p className="text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
                        {product?.description}
                      </p>
                    </div>
                  </div>

                  {/* Price & Cart CTA */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-neutral-200/60 dark:border-neutral-800/60">
                    <div className="flex flex-col">
                      <span className="text-xs font-semibold tracking-wider text-neutral-500 dark:text-neutral-400 uppercase">
                        Price
                      </span>
                      <span className="text-3xl font-black text-neutral-900 dark:text-white tracking-tight mt-0.5">
                        {formatCurrency(product?.price)}
                      </span>
                    </div>

                    <Button
                      disabled={isLoading}
                      className="w-full sm:w-auto px-8 py-3.5 rounded-full bg-neutral-900 text-white font-semibold shadow-lg hover:bg-neutral-800 hover:scale-[1.02] active:scale-95 focus:outline-none dark:bg-white dark:text-black dark:hover:bg-neutral-100 flex items-center justify-center gap-2 transition-all duration-300"
                      onClick={(e) => addToCart(e)}
                    >
                      {isLoading ? (
                        <ClipLoader
                          cssOverride={{
                            margin: "0 auto",
                          }}
                          color="currentColor"
                          size={20}
                        />
                      ) : (
                        <>
                          <ShoppingCart size={18} />
                          <span>Add to Cart</span>
                        </>
                      )}
                    </Button>
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

export default ProductDetails;
