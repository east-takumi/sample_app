class User < ApplicationRecord
	# インスタンス変数の定義
	attr_accessor :remember_token, :activation_token # 記憶トークンと有効化トークンを定義
  # before_save { email.downcase! }
  before_save :downcase_email # DB保存前にemailの値を小文字に変換する
  before_create :create_activation_digest # 作成前に適用
  validates :name, presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 }, format: { with:  VALID_EMAIL_REGEX }, uniqueness: { case_sensitive: false }
  has_secure_password
  validates :password, presence: true, length: { minimum: 6 }, allow_nil: true

  # 渡された文字列のハッシュ値を返す
  def User.digest(string)
  	cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST : BCrypt::Engine.cost
  	BCrypt::Password.create(string, cost: cost)
  end

  # ランダムなトークンを返す
  def User.new_token
  	SecureRandom.urlsafe_base64
  end

  # 記憶トークンをUserオブジェクトのremember_token属性に代入し、DBに記憶ダイジェストとして保存
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end

  # 渡されたトークンがダイジェストと一致したらtrueを返す
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end

  # ユーザーのログイン情報を破棄する
  def forget
  	update_attribute(:remember_digest, nil)
  end

  private

    # メールアドレスをすべて小文字にする
    def downcase_email
      self.email = email.downcase # emailを小文字化してUserオブジェクトのemail属性に代入
      # email.downcase! # emailを小文字化してUserオブジェクトのemail属性に代入
    end

    # 有効化トークンとダイジェストを作成および代入する
    def create_activation_digest
      self.activation_token = User.new_token # ハッシュ化した記憶トークンを有効化トークン属性に代入
      self.activation_digest = User.digest(activation_token) # 有効化トークンをBcryptで暗号化し、有効化ダイジェスト属性に代入
    end
end
