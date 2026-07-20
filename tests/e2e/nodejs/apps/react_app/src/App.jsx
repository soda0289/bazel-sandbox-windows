import React, { useState } from "react";

export default function App() {
  const [count, setCount] = useState(0);
  return (
    <div>
      <h1>Hello from the e2e React app</h1>
      <button onClick={() => setCount((c) => c + 1)}>count is {count}</button>
    </div>
  );
}
