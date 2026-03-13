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
    <>
      <img
        src={QIMA_LOGIN_LOGO}
        alt="QIMA GPT"
        className="mx-auto mb-2 h-14 w-14 shrink-0 rounded-lg bg-[#00AB76] p-1.5 sm:h-16 sm:w-16"
      />
      {error && (
        <div
          className="relative mb-2 rounded border border-red-400 bg-red-100 px-3 py-2 text-sm text-red-700"
          role="alert"
        >
          {localize(getLoginError(error))}
        </div>
      )}
    </>
  );
}

export default Login;
