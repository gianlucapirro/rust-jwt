import React, { useState } from "react";
import { Dialog, DialogPanel } from "@headlessui/react";
import { Bars3Icon, XMarkIcon } from "@heroicons/react/24/outline";
import { AuthService } from "~/api/services/AuthService";
import { useNavigate } from "react-router";
import type { UserResponse } from "~/api/models/UserResponse";

const navigation = [];

export default function Header({ user }: { user: UserResponse }) {
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const handleLogout = async () => {
    setError(null);

    try {
      await AuthService.logout();
      navigate("/login");
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Logout failed");
    }
  };

  return (
    <header className="bg-white">
      <nav
        aria-label="Global"
        className="flex items-center justify-between p-4 lg:px-0"
      >
        <div className="flex lg:flex-1">
          <a href="/" className="-m-1.5 p-1.5">
            <p className="text-xl font-bold">RUST API APP</p>
          </a>
        </div>
        <div className="flex lg:hidden">
          <button
            type="button"
            onClick={() => setMobileMenuOpen(true)}
            className="-m-2.5 inline-flex items-center justify-center rounded-md p-2.5 text-gray-700"
          >
            <span className="sr-only">Open main menu</span>
            <Bars3Icon aria-hidden="true" className="h-6 w-6" />
          </button>
        </div>
        <div className="hidden lg:flex lg:gap-x-12">
          {navigation.map((item) => (
            <a
              key={item.name}
              href={item.href}
              className="text-sm/6 font-semibold text-gray-900"
            >
              {item.name}
            </a>
          ))}
        </div>
        <div className="hidden lg:flex lg:flex-1 lg:justify-end">
          <div className="flex items-center gap-x-4">
            <span className="text-sm/6 font-semibold text-gray-900">
              {user.email}
            </span>
            <button
              onClick={handleLogout}
              className="text-sm/6 font-semibold text-gray-900"
            >
              Log out <span aria-hidden="true">&rarr;</span>
            </button>
          </div>
        </div>
      </nav>

      <Dialog
        open={mobileMenuOpen}
        onClose={setMobileMenuOpen}
        className="lg:hidden"
      >
        <div className="fixed inset-0 z-10" />
        <DialogPanel className="fixed inset-y-0 right-0 z-10 w-full overflow-y-auto bg-white px-6 py-6 sm:max-w-sm sm:ring-1 sm:ring-gray-900/10">
          <div className="flex items-center justify-between">
            <a href="/" className="-m-1.5 p-1.5">
              <p className="text-xl font-bold">RUST API APP</p>
            </a>
            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              className="-m-2.5 rounded-md p-2.5 text-gray-700"
            >
              <span className="sr-only">Close menu</span>
              <XMarkIcon aria-hidden="true" className="h-6 w-6" />
            </button>
          </div>
          <div className="mt-6 flow-root">
            <div className="-my-6 divide-y divide-gray-500/10">
              <div className="space-y-2 py-6">
                {navigation.map((item) => (
                  <a
                    key={item.name}
                    href={item.href}
                    className="-mx-3 block rounded-lg px-3 py-2 text-base/7 font-semibold text-gray-900 hover:bg-gray-50"
                  >
                    {item.name}
                  </a>
                ))}
              </div>
            </div>
          </div>
        </DialogPanel>
      </Dialog>
    </header>
  );
}
