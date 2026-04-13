export function useAuth() {
  const token = localStorage.getItem("token");

  const isAuthenticated = !!token;

  const login = (token: string) => {
    localStorage.setItem("token", token);
  };

  const logout = () => {
    localStorage.removeItem("token");
  };

  return {
    token,
    isAuthenticated,
    login,
    logout,
  };
}