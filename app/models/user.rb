class User < ApplicationRecord
	attr_accessor :remember_token
	before_save { self.email = email.downcase }
	# before_save { email.downcase! } # もう一つのコールバック処理
	validates :name, presence: true, length: { maximum: 50 }
	VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
	validates :email, presence: true, length: { maximum: 255 },
		format: { with: VALID_EMAIL_REGEX}, 
		uniqueness: { case_sensitive: false }
	has_secure_password
	validates :password, presence: true, length: { minimum: 6 }

	# 渡された文字列のハッシュを返す
	def User.digest(string) # 明示的な書き方
	# def self.digest(string) # ややわかりにくい書き方
		cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST : BCrypt::Engine.cost
		BCrypt::Password.create(string, cost: cost)
	end

	# ランダムなトークンを返す
	def User.new_token
	# def self.new_token # ややわかりにくい書き方
		SecureRandom.urlsafe_base64
	end

	# 一括でクラスメソッドを定義するやり方
	# class << self
		# # 渡された文字列のハッシュを返す
		# def digest(string)
			# cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST : BCrypt::Engine.cost
			# BCrypt::Password.create(string, cost: cost)
		# end

		# # ランダムなトークンを返す
		# def new_token
			# SecureRandom.urlsafe_base64
		# end
	# end

	# 永続セッションのためにユーザをデータベースに記憶する
	def remember
		self.remember_token = User.new_token
		update_attribute(:remember_digest, User.digest(remember_token))
	end

	# 渡されたトークンが(ハッシュ化し?)ダイジェストと一致したらTrueを返す
	def authenticated?(remember_token)
		return false if remember_digest.nil?
		BCrypt::Password.new(remember_digest).is_password?(remember_token)
	end	

	def forget
		update_attribute(:remember_digest, nil)
	end
end
