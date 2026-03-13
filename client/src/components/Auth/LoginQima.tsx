import React, { useEffect } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { useAuthContext } from '~/hooks/AuthContext';
import { useLocalize } from '~/hooks';
import { getLoginError } from '~/utils';
import type { TLoginLayoutContext } from '~/common';

const QIMA_LOGIN_LOGO = '/assets/qima-login-logo.svg';

function Login() {
  const { error, isAuthenticated } = useAuthContext();
  useOutletContext<TLoginLayoutContext>();
  const localize = useLocalize();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/chat/new', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-white pt-6 sm:pt-0">
      <div className="mt-6 flex w-96 flex-col items-center overflow-hidden bg-white px-6 py-4 sm:max-w-md sm:rounded-lg">
        <img
          src={QIMA_LOGIN_LOGO}
          alt="QIMA GPT"
          className="mb-6 h-[90px] w-[90px] rounded-[8px] bg-[#00AB76] p-2 text-center"
        />
        {error && (
          <div
            className="relative mt-4 rounded border border-red-400 bg-red-100 px-4 py-3 text-red-700"
            role="alert"
          >
            {localize(getLoginError(error))}
          </div>
        )}
      </div>
    </div>
  );
}

export default Login;
