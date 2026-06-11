import {
  Backdrop,
  Button,
  HelperText,
  Input,
  Label,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
} from "@windmill/react-ui";
import AccountForm from "components/AccountForm";
import { useUser } from "context/UserContext";
import Layout from "layout/Layout";
import { useState } from "react";
import { Edit2 } from "react-feather";
import toast from "react-hot-toast";
import PulseLoader from "react-spinners/PulseLoader";
import authService from "services/auth.service";

const Account = () => {
  const { userData } = useUser();
  const [showSettings, setShowSettings] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isMfaSetupOpen, setIsMfaSetupOpen] = useState(false);
  const [mfaSetupPassword, setMfaSetupPassword] = useState("");
  const [mfaSetupError, setMfaSetupError] = useState("");
  const [mfaSetupLoading, setMfaSetupLoading] = useState(false);
  const [mfaQrCode, setMfaQrCode] = useState("");
  const [mfaOtpAuthUrl, setMfaOtpAuthUrl] = useState("");
  const [mfaVerifyCode, setMfaVerifyCode] = useState("");
  const [mfaVerifyError, setMfaVerifyError] = useState("");
  const [mfaVerifyLoading, setMfaVerifyLoading] = useState(false);
  const [isRemoveMfaOpen, setIsRemoveMfaOpen] = useState(false);
  const [isRemoveMfaLoading, setIsRemoveMfaLoading] = useState(false);

  const resetPassword = () => {
    setIsSending(true);
    authService
      .forgotPassword(userData.email)
      .then((data) => {
        if (data.data.status === "OK") {
          setIsSending(false);
          toast.success("Email has been sent successfully.");
        }
      })
      .catch(() => {
        setIsSending(false);
        toast.error("An error occured. Please try again.");
      });
  };

  const openMfaSetup = () => {
    setIsMfaSetupOpen(true);
    setMfaSetupError("");
    setMfaVerifyError("");
    setMfaQrCode("");
    setMfaOtpAuthUrl("");
    setMfaVerifyCode("");
    setMfaSetupPassword("");
  };

  const closeMfaSetup = () => {
    setIsMfaSetupOpen(false);
    setMfaSetupError("");
    setMfaVerifyError("");
    setMfaSetupLoading(false);
    setMfaVerifyLoading(false);
    setMfaSetupPassword("");
  };

  const handleRemoveMfa = async () => {
    try {
      setIsRemoveMfaLoading(true);
      await authService.removeMfa();
      toast.success("MFA disabled. Please log in again.");
      setIsRemoveMfaOpen(false);
      // window.location.href = "/";
    } catch (error) {
      const res = error.response;
      toast.error(res?.data?.message || "Unable to disable MFA");
    } finally {
      setIsRemoveMfaLoading(false);
    }
  };

  const handleMfaSetup = async (event) => {
    event.preventDefault();
    if (!userData?.email) {
      setMfaSetupError("Unable to load your email. Please refresh.");
      return;
    }

    if (!mfaSetupPassword) {
      setMfaSetupError("Password is required");
      return;
    }

    try {
      setMfaSetupError("");
      setMfaSetupLoading(true);
      const data = await authService.mfaSetup(userData.email, mfaSetupPassword);
      setMfaQrCode(data.qrCodeDataUrl || "");
      setMfaOtpAuthUrl(data.otpauthUrl || "");
    } catch (error) {
      const res = error.response;
      setMfaSetupError(res?.data?.message || "Unable to start MFA setup");
    } finally {
      setMfaSetupLoading(false);
    }
  };

  const handleMfaVerify = async (event) => {
    event.preventDefault();
    if (!userData?.email) {
      setMfaVerifyError("Unable to load your email. Please refresh.");
      return;
    }

    if (!mfaVerifyCode) {
      setMfaVerifyError("MFA code is required");
      return;
    }

    try {
      setMfaVerifyError("");
      setMfaVerifyLoading(true);
      await authService.mfaVerify(userData.email, mfaSetupPassword, mfaVerifyCode);
      toast.success("MFA enabled. Please log in again.");
      closeMfaSetup();
    } catch (error) {
      const res = error.response;
      setMfaVerifyError(res?.data?.message || "Unable to verify MFA code");
    } finally {
      setMfaVerifyLoading(false);
    }
  };

  const displayValue = (value) => {
    return value && value.toString().trim() !== "" ? value : "Not provided";
  };

  return (
    <Layout title="Profile" loading={userData === null}>
      {showSettings ? (
        <AccountForm userData={userData} setShowSettings={setShowSettings} />
      ) : (
        <div className="w-full min-h-[85vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl animate-fade-in">
          {/* Background glow matching Vantage theme */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

          <div className="relative w-full max-w-4xl z-10">
            <div className="rounded-3xl border border-neutral-200/80 bg-white/70 p-8 md:p-10 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 flex flex-col gap-8 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
              
              {/* Top Profile Section */}
              <div className="flex flex-col sm:flex-row items-center gap-6 pb-8 border-b border-neutral-200/60 dark:border-neutral-800/60">
                <div className="w-20 h-20 sm:w-24 sm:h-24 rounded-full bg-gradient-to-tr from-emerald-500 to-teal-500 dark:from-emerald-600 dark:to-teal-600 flex items-center justify-center text-white text-3xl sm:text-4xl font-extrabold shadow-lg uppercase select-none ring-4 ring-emerald-500/10 dark:ring-emerald-500/20 transition-transform duration-300 hover:rotate-12">
                  {userData?.username?.[0] || userData?.fullname?.[0] || "?"}
                </div>
                <div className="flex flex-col items-center sm:items-start text-center sm:text-left gap-1.5">
                  <div className="flex flex-wrap items-center justify-center sm:justify-start gap-3">
                    <h2 className="text-2xl sm:text-3xl font-black text-neutral-955 dark:text-white tracking-tight">
                      {userData?.fullname}
                    </h2>
                    {userData?.is_mfa_enabled ? (
                      <span className="inline-flex items-center px-3 py-0.5 rounded-full text-xs font-semibold bg-emerald-100/85 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-205 dark:border-emerald-900/50">
                        MFA Enabled
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-3 py-0.5 rounded-full text-xs font-semibold bg-neutral-150 text-neutral-600 dark:bg-neutral-800/50 dark:text-emerald-400 border border-neutral-200/60 dark:border-neutral-700/50">
                        MFA Disabled
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-medium text-neutral-500 dark:text-neutral-450">
                    {userData?.username ? `@${userData.username}` : "Not provided"}
                  </p>
                  <p className="text-sm text-neutral-400 dark:text-neutral-550">
                    {userData?.email}
                  </p>
                </div>
              </div>

              {/* Sections Container */}
              <div className="flex flex-col gap-10">
                
                {/* SECTION 1: PERSONAL INFORMATION */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-xs font-extrabold uppercase tracking-widest text-neutral-400 dark:text-neutral-550">
                    Personal Information
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">Full Name</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200">
                        {displayValue(userData?.fullname)}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <span className="text-xs font-semibold text-neutral-455 dark:text-neutral-500">Username</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200">
                        {userData?.username ? `@${userData.username}` : "Not provided"}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <span className="text-xs font-semibold text-neutral-455 dark:text-neutral-500">Email Address</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200">
                        {displayValue(userData?.email)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* SECTION 2: SECURITY */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-xs font-extrabold uppercase tracking-widest text-neutral-400 dark:text-neutral-550">
                    Security Settings
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Password Reset */}
                    <div className="flex flex-col gap-5 p-5 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 justify-between transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <div>
                        <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">Password</span>
                        <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                          Request a secure password reset link sent directly to your inbox.
                        </p>
                      </div>
                      <Button
                        disabled={isSending}
                        onClick={resetPassword}
                        className="w-full sm:w-fit px-5 py-2.5 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm text-neutral-700 dark:text-neutral-300 transition-all flex items-center justify-center gap-2"
                      >
                        {isSending ? (
                          <PulseLoader color={"currentColor"} size={8} />
                        ) : (
                          "Reset Password by Email"
                        )}
                      </Button>
                    </div>

                    {/* MFA Section */}
                    <div className="flex flex-col gap-5 p-5 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 justify-between transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">Multi-Factor Authentication</span>
                          {userData?.is_mfa_enabled && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-405 border border-emerald-250 dark:border-emerald-900/50">
                              ✓ Active
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                          Add an extra layer of security to prevent unauthorized access.
                        </p>
                      </div>
                      
                      {userData?.is_mfa_enabled ? (
                        <Button
                          disabled={isRemoveMfaLoading}
                          onClick={() => setIsRemoveMfaOpen(true)}
                          className="w-full sm:w-fit px-5 py-2.5 rounded-xl border border-red-205 dark:border-red-900/50 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 font-semibold text-sm transition-all flex items-center justify-center gap-2"
                        >
                          {isRemoveMfaLoading ? (
                            <PulseLoader size={8} color={"currentColor"} />
                          ) : (
                            "Disable MFA"
                          )}
                        </Button>
                      ) : (
                        <Button
                          disabled={!userData?.email}
                          onClick={openMfaSetup}
                          className="w-full sm:w-fit px-5 py-2.5 rounded-xl bg-[#01A982] text-white hover:bg-[#019371] font-semibold text-sm shadow transition-all duration-300 hover:scale-[1.01] active:scale-95 flex items-center justify-center gap-2"
                        >
                          Enable MFA
                        </Button>
                      )}
                    </div>
                  </div>
                </div>

                {/* SECTION 3: ADDRESS INFORMATION */}
                <div className="flex flex-col gap-4">
                  <h3 className="text-xs font-extrabold uppercase tracking-widest text-neutral-400 dark:text-neutral-550">
                    Address Information
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6">
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30 col-span-1 sm:col-span-2">
                      <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">Address</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200 line-clamp-2">
                        {displayValue(userData?.address)}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">City</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200">
                        {displayValue(userData?.city)}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30">
                      <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">State</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200">
                        {displayValue(userData?.state)}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1.5 p-4 rounded-2xl bg-white/50 dark:bg-neutral-950/20 border border-neutral-200/60 dark:border-neutral-900/40 transition-all hover:bg-neutral-50/50 dark:hover:bg-neutral-950/30 md:col-span-2 lg:col-span-1">
                      <span className="text-xs font-semibold text-neutral-450 dark:text-neutral-500">Country</span>
                      <span className="text-sm font-medium text-neutral-850 dark:text-neutral-200">
                        {displayValue(userData?.country)}
                      </span>
                    </div>
                  </div>
                </div>

              </div>

              {/* Edit Profile Button */}
              <div className="flex justify-end pt-6 border-t border-neutral-200/60 dark:border-neutral-800/60 mt-4">
                <Button
                  onClick={() => setShowSettings(true)}
                  className="px-6 py-3.5 rounded-xl bg-[#01A982] text-white hover:bg-[#019371] font-semibold shadow-lg transition-all duration-300 hover:scale-[1.02] active:scale-95 flex items-center gap-2"
                >
                  <Edit2 size={16} />
                  Edit Profile
                </Button>
              </div>

            </div>
          </div>
        </div>
      )}
      {(isMfaSetupOpen || isRemoveMfaOpen) && <Backdrop />}
      <Modal isOpen={isRemoveMfaOpen} onClose={() => setIsRemoveMfaOpen(false)}>
        <ModalHeader className="text-lg font-bold text-neutral-955 dark:text-white">Disable Multi-factor Authentication</ModalHeader>
        <ModalBody className="mt-2 text-sm text-neutral-600 dark:text-neutral-400">
          <p>
            Are you sure you want to disable MFA? Your account will be less secure.
          </p>
        </ModalBody>
        <ModalFooter className="flex gap-3 justify-end mt-6">
          <Button
            layout="outline"
            onClick={() => setIsRemoveMfaOpen(false)}
            disabled={isRemoveMfaLoading}
            className="px-5 py-2.5 rounded-xl border border-neutral-200 dark:border-neutral-800 text-neutral-700 dark:text-neutral-350 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm transition-all"
          >
            Cancel
          </Button>
          <Button 
            onClick={handleRemoveMfa} 
            disabled={isRemoveMfaLoading}
            className="px-5 py-2.5 rounded-xl bg-red-650 text-white hover:bg-red-705 font-semibold shadow-md transition-all flex items-center justify-center min-w-[100px]"
          >
            {isRemoveMfaLoading ? <PulseLoader size={8} color={"#ffffff"} /> : "Disable"}
          </Button>
        </ModalFooter>
      </Modal>
      <Modal isOpen={isMfaSetupOpen} onClose={closeMfaSetup}>
        <ModalHeader className="text-lg font-bold text-neutral-955 dark:text-white">Enable MFA</ModalHeader>
        <ModalBody className="mt-3">
          {!mfaQrCode ? (
            <form onSubmit={handleMfaSetup} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <Label className="text-sm font-semibold text-neutral-700 dark:text-neutral-300">
                  <span>Password</span>
                </Label>
                <Input
                  className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-650 dark:focus:border-white dark:focus:ring-white transition duration-200"
                  type="password"
                  value={mfaSetupPassword}
                  onChange={(event) => setMfaSetupPassword(event.target.value)}
                  placeholder="Enter your account password"
                />
              </div>
              {mfaSetupError && (
                <HelperText className="text-xs italic text-red-500 dark:text-red-400" valid={false}>
                  {mfaSetupError}
                </HelperText>
              )}
              <ModalFooter className="flex justify-end gap-3 pt-4 border-t border-neutral-200/60 dark:border-neutral-800/60 mt-2">
                <Button
                  layout="outline"
                  onClick={closeMfaSetup}
                  disabled={mfaSetupLoading}
                  className="px-5 py-2.5 rounded-xl border border-neutral-200 dark:border-neutral-800 text-neutral-700 dark:text-neutral-350 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm transition-all"
                >
                  Cancel
                </Button>
                <Button 
                  type="submit" 
                  disabled={mfaSetupLoading}
                  className="px-5 py-2.5 rounded-xl bg-[#01A982] text-white hover:bg-[#019371] font-semibold shadow-md transition-all duration-300 hover:scale-[1.01] active:scale-95 flex items-center justify-center min-w-[120px]"
                >
                  {mfaSetupLoading ? <PulseLoader size={8} color={"#ffffff"} /> : "Generate QR"}
                </Button>
              </ModalFooter>
            </form>
          ) : (
            <form onSubmit={handleMfaVerify} className="flex flex-col gap-5">
              <div className="flex flex-col items-center gap-3">
                <div className="p-2 bg-white rounded-2xl border border-neutral-200 dark:border-neutral-800">
                  <img src={mfaQrCode} alt="MFA QR code" className="h-44 w-44" />
                </div>
                {mfaOtpAuthUrl && (
                  <p className="text-xs mt-1 break-all text-center text-neutral-500 dark:text-neutral-405 max-w-sm">
                    {mfaOtpAuthUrl}
                  </p>
                )}
              </div>
              <div className="flex flex-col gap-1.5">
                <Label className="text-sm font-semibold text-neutral-750 dark:text-neutral-350">
                  <span>MFA Code</span>
                </Label>
                <Input
                  className="w-full px-4 py-3 text-sm rounded-xl border border-neutral-200 bg-white/50 text-neutral-900 placeholder-neutral-400 focus:border-black focus:ring-1 focus:ring-black focus:outline-none dark:border-neutral-800 dark:bg-neutral-950/50 dark:text-white dark:placeholder-neutral-650 dark:focus:border-white dark:focus:ring-white transition duration-200 text-center tracking-[0.2em] text-lg font-bold"
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaVerifyCode}
                  onChange={(event) => setMfaVerifyCode(event.target.value)}
                  placeholder="000000"
                />
              </div>
              {mfaVerifyError && (
                <HelperText className="text-xs italic text-red-500 dark:text-red-400" valid={false}>
                  {mfaVerifyError}
                </HelperText>
              )}
              <ModalFooter className="flex justify-end gap-3 pt-4 border-t border-neutral-200/60 dark:border-neutral-800/60 mt-2">
                <Button
                  layout="outline"
                  onClick={closeMfaSetup}
                  disabled={mfaVerifyLoading}
                  className="px-5 py-2.5 rounded-xl border border-neutral-205 dark:border-neutral-800 text-neutral-700 dark:text-neutral-355 hover:bg-neutral-50 dark:hover:bg-neutral-900 font-semibold text-sm transition-all"
                >
                  Cancel
                </Button>
                <Button 
                  type="submit" 
                  disabled={mfaVerifyLoading}
                  className="px-5 py-2.5 rounded-xl bg-[#01A982] text-white hover:bg-[#019371] font-semibold shadow-md transition-all duration-300 hover:scale-[1.01] active:scale-95 flex items-center justify-center min-w-[150px]"
                >
                  {mfaVerifyLoading ? (
                    <PulseLoader size={8} color={"#ffffff"} />
                  ) : (
                    "Verify and Enable"
                  )}
                </Button>
              </ModalFooter>
            </form>
          )}
        </ModalBody>
      </Modal>
    </Layout>
  );
};

export default Account;
