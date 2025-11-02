import type { Route } from "./+types/_protected._index";
import { redirect, useOutletContext } from "react-router";
import type { ProtectedOutletContext } from "./_protected";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "New React Router App" },
    { name: "description", content: "Welcome to React Router!" },
  ];
}

export default function Index() {
  const { user } = useOutletContext<ProtectedOutletContext>();
  return <p>Welcome {user?.name}</p>;
}
