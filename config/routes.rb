Rails.application.routes.draw do
  get 'sessions/new'

  # get 'users/new'

  root 'static_pages#home'
  get  '/help',    to: 'static_pages#help'
  get  '/about',   to: 'static_pages#about'
  get  '/contact', to: 'static_pages#contact'
  get  '/signup',  to: 'users#new'
  # post  '/signup',  to: 'users#create'              #createアクションの時`signup`を取得
  get '/login', to: 'sessions#new'
  post '/login', to: 'sessions#create'
  delete '/logout', to:'sessions#destroy'
  resources :users
  resource :account_activations, only: [:edit]
end