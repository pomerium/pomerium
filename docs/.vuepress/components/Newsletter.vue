<template>
  <SimpleNewsletter v-slot="{ slotProps }">
  <div class="newsletter__wrap">
    <div class="my-title">{{ slotProps.title }}</div>
    <div class="my-content">{{ slotProps.content }}</div>
    <input
      class="my-input"
      type="email"
      name="email"
      aria-label="Email"
      placeholder="Email"
      v-model="slotProps.mail"
      required
      autocapitalize="off"
      autocorrect="off"
      data-cy="email"
    />
    <button type="submit" class="my-button" data-cy="submit">
      {{ slotProps.submitText }}
    </button>
  </div>
  </SimpleNewsletter>
</template>


<style>
.my-title {
  font-size: 1.7rem;
  display: block;
  text-align: center;

}
.my-content {
  margin-top: 1.5rem;
  margin-bottom: 1.5rem;
  line-height: 1.7rem;
}
.my-input {
  font-size: inherit;
  border: 1px solid #e8e8fb;
  padding: 0.6rem 1.2rem;
  box-sizing: border-box;
  border-radius: 3px;
  margin-bottom: 0.8rem;
  outline: none;
}

.my-button {
    font-size: inherit;
    border: none;
    cursor: pointer;
    background: #6f43e7;
    color: #fff;
    padding: 0.6rem 1.8rem;
    box-sizing: border-box;
    border-radius: 3px;
    outline: none;
}


</style>